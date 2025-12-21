use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use once_cell::sync::OnceCell;
use std::path::Path;
use std::sync::Arc;
use tatu_common::keys;
use tatu_common::model::Persona;
use tatu_common::noise::NoisePipe;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:25519";
const DEFAULT_BACKEND_ADDR: &str = "127.0.0.1:25564";
const DEFAULT_KEY_PATH: &str = "tatu-server.key";

static BACKEND_ADDR: OnceCell<String> = OnceCell::new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let listen_addr = args
        .get(1)
        .map(String::as_str)
        .unwrap_or(DEFAULT_LISTEN_ADDR);
    let backend_addr = args
        .get(2)
        .map(String::as_str)
        .unwrap_or(DEFAULT_BACKEND_ADDR);
    let key_path =
        std::env::var("TATU_SERVER_KEY").unwrap_or_else(|_| DEFAULT_KEY_PATH.to_string());

    BACKEND_ADDR.set(backend_addr.to_string()).unwrap();

    let keypair = Arc::new(keys::TatuKey::load_or_generate(Path::new(&key_path))?);
    tracing::info!("Server key: {}", keypair);
    tracing::info!("Post this to multiple independent channels for enchanced protection!");

    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("Listening on {listen_addr}, backend at {backend_addr}");

    loop {
        let (stream, addr) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let keypair = Arc::clone(&keypair);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, &keypair).await {
                tracing::error!("Connection error from {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    client_addr: std::net::SocketAddr,
    keypair: &keys::TatuKey,
) -> anyhow::Result<()> {
    let (client, persona) = authenticate_client(stream, keypair).await?;
    tracing::info!("{} connected from {}", persona, client_addr.ip());

    let backend_conn = minecraft_login(&persona, client_addr.ip()).await?;

    tracing::info!("{} joined", persona.handle);
    let result = forward_messages(client, backend_conn).await;
    tracing::info!("{} left", persona.handle);

    result
}

async fn authenticate_client(
    stream: TcpStream,
    keypair: &keys::TatuKey,
) -> anyhow::Result<(NoisePipe<TcpStream>, Persona)> {
    use futures::StreamExt;
    use tatu_common::model::AuthMessage;

    let mut secure_stream = NoisePipe::accept(stream, &keypair.x_key()).await?;
    let client_key = secure_stream.remote_public_key()?;

    let auth_bytes = secure_stream
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed before auth"))??;
    let auth_msg: AuthMessage = rmp_serde::from_slice(&auth_bytes)?;

    let persona = Persona::auth(client_key, auth_msg.handle_claim, auth_msg.skin)?;
    Ok((secure_stream, persona))
}

async fn minecraft_login(
    persona: &Persona,
    client_ip: std::net::IpAddr,
) -> anyhow::Result<(
    azalea::protocol::connect::RawReadConnection,
    azalea::protocol::connect::RawWriteConnection,
)> {
    use azalea::protocol::{
        connect::Connection,
        packets::{
            ClientIntention,
            handshake::{ServerboundHandshakePacket, s_intention::ServerboundIntention},
            login::{ServerboundLoginPacket, s_hello::ServerboundHello},
        },
    };

    let backend_addr = BACKEND_ADDR.get().unwrap();
    let stream = TcpStream::connect(backend_addr.as_str()).await?;
    stream.set_nodelay(true)?;

    let mut conn = Connection::wrap(stream);

    let backend_port = backend_addr
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(25565);

    conn.write(ServerboundHandshakePacket::Intention(
        ServerboundIntention {
            hostname: bungeecord_hostname(client_ip, persona.uuid(), persona.skin.clone()),
            protocol_version: azalea::protocol::packets::PROTOCOL_VERSION,
            port: backend_port,
            intention: ClientIntention::Login,
        },
    ))
    .await?;

    let mut login_conn = conn.login();
    login_conn
        .write(ServerboundLoginPacket::Hello(ServerboundHello {
            name: persona.handle.to_string(),
            profile_id: Uuid::nil(),
        }))
        .await?;

    Ok(login_conn.into_split_raw())
}

fn bungeecord_hostname(client_ip: std::net::IpAddr, uuid: Uuid, skin: Option<String>) -> String {
    format!(
        "localhost\0{client_ip}\0{}\0{}",
        uuid.as_hyphenated(),
        skin.unwrap_or("[]".to_string())
    )
}

// NOTE: forward_messages duped between client/server. Should it be in common?
async fn forward_messages(
    client: NoisePipe<TcpStream>,
    backend: (
        azalea::protocol::connect::RawReadConnection,
        azalea::protocol::connect::RawWriteConnection,
    ),
) -> anyhow::Result<()> {
    let (mut backend_read, mut backend_write) = backend;
    let (mut client_sink, mut client_stream) = client.split();

    loop {
        tokio::select! {
            client_msg = client_stream.next() => {
                match client_msg {
                    Some(Ok(bytes)) => {
                        backend_write.write(&bytes).await?;
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                }
            }
            backend_msg = backend_read.read() => {
                match backend_msg {
                    Ok(bytes) => {
                        client_sink.send(Bytes::from(bytes)).await?;
                        client_sink.flush().await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(())
}
