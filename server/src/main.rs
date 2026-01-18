use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use argh::FromArgs;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use shadow_rs::shadow;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use azalea_protocol::{
    connect::{Connection, RawReadConnection, RawWriteConnection},
    packets::{
        handshake::{ServerboundHandshakePacket, s_intention::ServerboundIntention},
        login::{ServerboundLoginPacket, s_hello::ServerboundHello},
    },
    read::deserialize_packet,
};
use tatu_common::{
    keys::TatuKey,
    model::{AuthMessage, Persona},
    noise::NoisePipe,
};

shadow!(build);

fn print_banner(fields: &[(&str, &dyn std::fmt::Display)]) {
    for (key, value) in fields {
        eprintln!("{}: {}", key, value);
    }
    eprintln!();
}

#[derive(FromArgs)]
/// Tatu server proxy
///
/// Environment variables:
///   TATU_SERVER_KEY    Path to server identity key
struct Args {
    #[argh(positional, default = "String::from(\"127.0.0.1:25564\")")]
    /// backend Minecraft server address
    backend_addr: String,

    #[argh(option, short = 'l', default = "String::from(\"0.0.0.0:25519\")")]
    /// listen address
    listen_addr: String,

    #[argh(option, short = 'k', default = "PathBuf::from(\"tatu-server.key\")")]
    /// path to server keyfile
    keyfile: PathBuf,
}

struct Runtime {
    backend_addr: Arc<str>,
    keypair: Arc<TatuKey>,
}

impl Runtime {
    fn load(args: Args) -> anyhow::Result<(String, String, Self, bool)> {
        let keyfile = std::env::var("TATU_SERVER_KEY")
            .ok()
            .map(PathBuf::from)
            .unwrap_or(args.keyfile);

        let (keypair, recovery_phrase) = TatuKey::load_or_generate(&keyfile, None)?;
        let keypair = Arc::new(keypair);
        let is_new_key = recovery_phrase.is_some();

        let runtime = Self {
            backend_addr: args.backend_addr.into(),
            keypair,
        };

        Ok((
            args.listen_addr,
            keyfile.display().to_string(),
            runtime,
            is_new_key,
        ))
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
    let args: Args = argh::from_env();
    let (listen_addr, keyfile, runtime, is_new_key) = Runtime::load(args)?;
    let runtime = Arc::new(runtime);

    let version = format!(
        "server v{} ({}/{}{})",
        build::PKG_VERSION,
        build::BRANCH,
        build::SHORT_COMMIT,
        if build::GIT_CLEAN { "" } else { "-dirty" }
    );

    print_banner(&[
        ("version", &version as &dyn std::fmt::Display),
        ("listening", &listen_addr),
        ("backend", &runtime.backend_addr),
        ("keyfile", &keyfile),
        ("key", &runtime.keypair),
    ]);

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    if is_new_key {
        tracing::warn!("new server key generated");
        tracing::warn!("tip: post this key to multiple independent channels!");
    }

    let listener = TcpListener::bind(&listen_addr).await?;

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
    client_addr: SocketAddr,
    rt: &Runtime,
) -> anyhow::Result<()> {
    let (client, persona, client_handshake) = authenticate_client(stream, &rt.keypair).await?;
    tracing::info!(name = %persona.handle, uuid = %persona.uuid(), ip = %client_addr.ip(), "authed");

    let backend_conn = minecraft_login(&persona, client_addr.ip(), &client_handshake, rt).await?;

    tracing::info!(name = %persona.handle, "joined");
    let result = forward_messages(client, backend_conn).await;
    tracing::info!(name = %persona.handle, "left");

    result
}

async fn authenticate_client(
    stream: TcpStream,
    keypair: &TatuKey,
) -> anyhow::Result<(NoisePipe<TcpStream>, Persona, ServerboundHandshakePacket)> {
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
    let client_handshake = deserialize_packet(&mut std::io::Cursor::new(&handshake_bytes[..]))?;

    let persona = Persona::auth(client_key, auth_msg.handle_claim, auth_msg.skin)?;
    Ok((secure_stream, persona, client_handshake))
}

async fn minecraft_login(
    persona: &Persona,
    client_ip: IpAddr,
    client_handshake: &ServerboundHandshakePacket,
    rt: &Runtime,
) -> anyhow::Result<(RawReadConnection, RawWriteConnection)> {
    let ServerboundHandshakePacket::Intention(intention) = client_handshake;
    let backend_handshake = ServerboundIntention {
        hostname: bungeecord_hostname(client_ip, persona.uuid(), persona.skin.clone()),
        port: rt.backend_port(),
        protocol_version: intention.protocol_version,
        intention: intention.intention,
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

fn bungeecord_hostname(client_ip: IpAddr, uuid: Uuid, skin: Option<String>) -> String {
    format!(
        "localhost\0{client_ip}\0{}\0{}",
        uuid.as_hyphenated(),
        skin.unwrap_or_else(|| "[]".to_string())
    )
}

async fn forward_messages(
    client: NoisePipe<TcpStream>,
    backend: (RawReadConnection, RawWriteConnection),
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
