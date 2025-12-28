use bytes::Bytes;
use clap::Parser;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tatu_common::keys::TatuKey;
use tatu_common::model::Persona;
use tatu_common::noise::NoisePipe;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

#[derive(Parser)]
#[command(about = "Tatu server proxy")]
struct Args {
    #[arg(default_value = "127.0.0.1:25564")]
    backend_addr: String,

    #[arg(long, default_value = "0.0.0.0:25519")]
    listen_addr: String,

    #[arg(long, env = "TATU_SERVER_KEY", default_value = "tatu-server.key")]
    key_path: std::path::PathBuf,
}

struct Runtime {
    backend_addr: Arc<str>,
    keypair: Arc<TatuKey>,
}

impl Runtime {
    fn load(args: Args) -> anyhow::Result<(String, Self)> {
        let (keypair, _) = TatuKey::load_or_generate(&args.key_path, None)?;
        let keypair = Arc::new(keypair);

        tracing::info!("Server key: {}", keypair);
        tracing::info!("Post this to multiple independent channels for enhanced protection!");

        let runtime = Self {
            backend_addr: args.backend_addr.into(),
            keypair,
        };

        Ok((args.listen_addr, runtime))
    }

    fn backend_port(&self) -> u16 {
        self.backend_addr
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(25565)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let (listen_addr, runtime) = Runtime::load(Args::parse())?;
    let runtime = Arc::new(runtime);

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        "Listening on {listen_addr}, backend at {}",
        runtime.backend_addr
    );

    loop {
        let (stream, addr) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, &runtime).await {
                tracing::error!("Connection error from {}: {e}", addr);
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    client_addr: std::net::SocketAddr,
    rt: &Runtime,
) -> anyhow::Result<()> {
    let (client, persona, client_handshake) = authenticate_client(stream, &rt.keypair).await?;
    tracing::info!("{} connected from {}", persona, client_addr.ip());

    let backend_conn = minecraft_login(&persona, client_addr.ip(), &client_handshake, rt).await?;

    tracing::info!("{} joined", persona.handle);
    let result = forward_messages(client, backend_conn).await;
    tracing::info!("{} left", persona.handle);

    result
}

async fn authenticate_client(
    stream: TcpStream,
    keypair: &TatuKey,
) -> anyhow::Result<(
    NoisePipe<TcpStream>,
    Persona,
    azalea::protocol::packets::handshake::ServerboundHandshakePacket,
)> {
    use azalea::protocol::read::deserialize_packet;
    use tatu_common::model::AuthMessage;

    let mut secure_stream = NoisePipe::accept(stream, &keypair.x_key()).await?;
    let client_key = secure_stream.remote_public_key()?;

    let auth_bytes = secure_stream
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed before auth"))??;
    let auth_msg: AuthMessage = rmp_serde::from_slice(&auth_bytes)?;

    let handshake_bytes = secure_stream
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed before handshake"))??;
    let mut cursor = std::io::Cursor::new(&handshake_bytes[..]);
    let client_handshake = deserialize_packet(&mut cursor)?;

    let persona = Persona::auth(client_key, auth_msg.handle_claim, auth_msg.skin)?;
    Ok((secure_stream, persona, client_handshake))
}

async fn minecraft_login(
    persona: &Persona,
    client_ip: std::net::IpAddr,
    client_handshake: &azalea::protocol::packets::handshake::ServerboundHandshakePacket,
    rt: &Runtime,
) -> anyhow::Result<(
    azalea::protocol::connect::RawReadConnection,
    azalea::protocol::connect::RawWriteConnection,
)> {
    use azalea::protocol::{
        connect::Connection,
        packets::{
            handshake::{ServerboundHandshakePacket, s_intention::ServerboundIntention},
            login::{ServerboundLoginPacket, s_hello::ServerboundHello},
        },
    };

    let backend_handshake = match client_handshake {
        ServerboundHandshakePacket::Intention(intention) => ServerboundIntention {
            hostname: bungeecord_hostname(client_ip, persona.uuid(), persona.skin.clone()),
            port: rt.backend_port(),
            protocol_version: intention.protocol_version,
            intention: intention.intention,
        },
    };

    let stream = TcpStream::connect(&*rt.backend_addr).await?;
    stream.set_nodelay(true)?;

    let mut conn = Connection::wrap(stream);

    conn.write(ServerboundHandshakePacket::Intention(backend_handshake))
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
        skin.unwrap_or_else(|| "[]".to_string())
    )
}

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
