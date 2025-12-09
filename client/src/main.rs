mod keychain;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use keychain::Keychain;
use once_cell::sync::OnceCell;
use std::path::PathBuf;
use std::sync::Arc;
use tatu_common::keys::{RemoteTatuKey, TatuKey};
use tatu_common::noise::NoisePipe;
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:25565";
const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:25519";

static PROXY_ADDR: OnceCell<String> = OnceCell::new();
static IDENTITY_KEY: OnceCell<Arc<TatuKey>> = OnceCell::new();
static HANDLES_DIR: OnceCell<PathBuf> = OnceCell::new();
static SERVERS_PIN_PATH: OnceCell<PathBuf> = OnceCell::new();

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
    let proxy_addr = args
        .get(2)
        .map(String::as_str)
        .unwrap_or(DEFAULT_PROXY_ADDR);

    PROXY_ADDR.set(proxy_addr.to_string()).unwrap();

    let identity_key_path = std::env::var("TATU_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("tatu-id.key"));
    let identity_key = Arc::new(tatu_common::keys::TatuKey::load_or_generate(
        &identity_key_path,
    )?);
    IDENTITY_KEY.set(identity_key).ok();

    HANDLES_DIR
        .set(
            std::env::var("TATU_HANDLES")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("tatu-handles")),
        )
        .unwrap();
    SERVERS_PIN_PATH
        .set(
            std::env::var("TATU_KNOWN_SERVERS")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("tatu-servers.pin")),
        )
        .unwrap();

    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("Client proxy listening on {listen_addr}, forwarding to {proxy_addr}");

    loop {
        let (stream, addr) = listener.accept().await?;
        stream.set_nodelay(true)?;

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, addr).await {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_client(
    stream: TcpStream,
    _client_addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let (mc_conn, nick) = read_minecraft_login(stream).await?;
    tracing::info!("Connecting as {}", nick);

    let proxy_addr = PROXY_ADDR.get().unwrap();
    let tcp_stream = TcpStream::connect(proxy_addr.as_str()).await?;
    tcp_stream.set_nodelay(true)?;

    let identity = IDENTITY_KEY.get().unwrap();
    let mut keychain = Keychain::new(
        identity.as_ref(),
        HANDLES_DIR.get().unwrap(),
        SERVERS_PIN_PATH.get().unwrap(),
    )?;

    let mut secure_pipe = NoisePipe::connect(tcp_stream, &keychain.identity.x_key()).await?;

    let server_key = RemoteTatuKey::from_x_pub(secure_pipe.remote_public_key()?);
    match keychain.id_server(proxy_addr, &server_key) {
        Ok(()) => {
            tracing::info!("Server key verified");
        }
        Err(keychain::PinError::NotKnown) => {
            tracing::warn!("Server not known, pinning key: {}", server_key);
            keychain.pin_server(proxy_addr.to_string(), server_key)?;
            tracing::info!("Verify this key through a trusted channel!")
        }
        Err(keychain::PinError::Mismatch) => {
            anyhow::bail!("Server key mismatch! Potential MITM attack detected");
        }
    }

    let auth_msg = tatu_common::model::AuthMessage {
        handle_claim: keychain.get_handle(&nick)?,
        skin: None, // TODO: Support custom skins
    };

    secure_pipe
        .send(Bytes::from(rmp_serde::to_vec(&auth_msg)?))
        .await?;

    tracing::info!("Connected to proxy server");
    let result = forward_messages(mc_conn, secure_pipe).await;
    tracing::info!("Disconnected");

    result
}

async fn read_minecraft_login(
    stream: TcpStream,
) -> anyhow::Result<(
    (
        azalea::protocol::connect::RawReadConnection,
        azalea::protocol::connect::RawWriteConnection,
    ),
    String,
)> {
    use azalea::protocol::{
        connect::Connection,
        packets::{handshake::ServerboundHandshakePacket, login::ServerboundLoginPacket},
        read::ReadPacketError,
    };

    let mut conn = Connection::wrap(stream);

    let _intent = match conn.read().await {
        Ok(ServerboundHandshakePacket::Intention(p)) => p,
        Err(_) => anyhow::bail!("Failed to read handshake"),
    };

    let mut conn = conn.login();
    let hello = loop {
        match conn.read().await {
            Ok(ServerboundLoginPacket::Hello(h)) => break h,
            Err(e) if matches!(*e, ReadPacketError::ConnectionClosed) => {
                anyhow::bail!("Connection closed during login")
            }
            Err(e) => return Err(e.into()),
            _ => {}
        }
    };

    let mut nick = hello.name.clone();
    nick.truncate(7);

    Ok((conn.into_split_raw(), nick))
}

async fn forward_messages(
    mc_conn: (
        azalea::protocol::connect::RawReadConnection,
        azalea::protocol::connect::RawWriteConnection,
    ),
    proxy: NoisePipe<TcpStream>,
) -> anyhow::Result<()> {
    let (mut mc_read, mut mc_write) = mc_conn;
    let (mut proxy_sink, mut proxy_stream) = proxy.split();

    loop {
        tokio::select! {
            mc_msg = mc_read.read() => {
                match mc_msg {
                    Ok(bytes) => {
                        proxy_sink.send(Bytes::from(bytes)).await?;
                        proxy_sink.flush().await?;
                    }
                    Err(e) if matches!(*e, azalea::protocol::read::ReadPacketError::ConnectionClosed) => {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            proxy_msg = proxy_stream.next() => {
                match proxy_msg {
                    Some(Ok(bytes)) => {
                        mc_write.write(&bytes).await?;
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                }
            }
        }
    }

    Ok(())
}
