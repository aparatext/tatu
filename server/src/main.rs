use argh::FromArgs;
use shadow_rs::shadow;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::{TcpListener, TcpStream};

use tatu_common::{
    keys::TatuKey,
    minecraft::ServerSidePlayer,
    model::{AuthMessage, Persona},
    noise::NoisePipe,
    framing::read_frame,
};

shadow!(build);

#[derive(FromArgs)]
/// tatu server proxy
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

        let (keypair, keyphrase) = TatuKey::load_or_generate(&keyfile, None)?;
        let keypair = Arc::new(keypair);
        let is_new_key = keyphrase.is_some();

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();
    let (listen_addr, keyfile, runtime, is_new_key) = Runtime::load(args)?;
    let runtime = Arc::new(runtime);

    eprintln!(
        "version: server v{} ({}/{}{})",
        build::PKG_VERSION,
        build::BRANCH,
        build::SHORT_COMMIT,
        if build::GIT_CLEAN { "" } else { "-dirty" }
    );
    eprintln!("listening: {}", listen_addr);
    eprintln!("backend: {}", runtime.backend_addr);
    eprintln!("keyfile: {}", keyfile);
    eprintln!("key: {}\n", runtime.keypair);

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
    tatu_stream: TcpStream,
    client_addr: SocketAddr,
    rt: &Runtime,
) -> anyhow::Result<()> {
    let (pipe, persona, handshake_bytes) = auth_client(tatu_stream, &rt.keypair).await?;
    tracing::info!(name = %persona.handle, uuid = %persona.uuid(), ip = %client_addr.ip(), "authed");

    let player = ServerSidePlayer::new(&persona, client_addr.ip());
    let backend = TcpStream::connect(&*rt.backend_addr).await?;
    let bridge = player.connect(backend, &handshake_bytes).await?;

    tracing::info!(name = %persona.handle, "joined");
    let result = bridge.forward(pipe).await;
    tracing::info!(name = %persona.handle, "left");

    result.map_err(Into::into)
}

async fn auth_client(
    tatu_stream: TcpStream,
    keypair: &TatuKey,
) -> anyhow::Result<(NoisePipe<TcpStream>, Persona, bytes::Bytes)> {
    let mut secure_stream = NoisePipe::accept(tatu_stream, &keypair.x_key()).await?;
    let client_key = secure_stream.remote_public_key()?;

    let auth_bytes = read_frame(&mut secure_stream)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Connection closed before auth"))?;
    let auth_msg: AuthMessage = rmp_serde::from_slice(&auth_bytes)?;

    let handshake_bytes = read_frame(&mut secure_stream)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Connection closed before handshake"))?;

    let persona = Persona::auth(client_key, auth_msg.handle_proof, auth_msg.skin)?;
    Ok((secure_stream, persona, handshake_bytes))
}
