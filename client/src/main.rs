mod keychain;

use argh::FromArgs;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use shadow_rs::shadow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

use azalea_protocol::{
    self as protocol,
    packets::{game::ClientboundGamePacket, handshake::ServerboundHandshakePacket},
    read::ReadPacketError,
    write::serialize_packet,
};

use keychain::Keychain;
use tatu_common::{
    keys::{RecoveryPhrase, RemoteTatuKey, TatuKey},
    model::AuthMessage,
    noise::NoisePipe,
};

shadow!(build);

fn print_banner(fields: &[(&str, &dyn std::fmt::Display)]) {
    for (key, value) in fields {
        eprintln!("{}: {}", key, value);
    }
    eprintln!();
}

type MCReadWriteConn = (
    azalea_protocol::connect::RawReadConnection,
    azalea_protocol::connect::RawWriteConnection,
);

const MAX_NICK_LENGTH: usize = 7;

#[derive(FromArgs)]
/// tatu client proxy
struct Cli {
    #[argh(subcommand)]
    mode: Mode,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Mode {
    Run(RunArgs),
    Recover(RecoverArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "run")]
/// Run the client proxy
struct RunArgs {
    #[argh(positional)]
    /// destination server address
    dest_addr: String,

    #[argh(option, short = 'l', default = "String::from(\"127.0.0.1:25565\")")]
    /// listen address (default: 127.0.0.1:25565)
    listen_addr: String,

    #[argh(option, short = 's')]
    /// path to skin file
    skin: Option<PathBuf>,

    #[argh(option, short = 'k')]
    /// path to keyfile
    keyfile: Option<PathBuf>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "recover")]
/// Recover identity from recovery phrase
struct RecoverArgs {
    #[argh(option, short = 'k')]
    /// path to keyfile
    keyfile: Option<PathBuf>,
}

struct Runtime {
    dest_addr: String,
    skin: Option<Arc<str>>,
    keychain: Arc<Keychain>,
    recovery_phrase: Mutex<Option<RecoveryPhrase>>,
}

fn resolve_paths(keyfile: Option<PathBuf>) -> (PathBuf, PathBuf, PathBuf) {
    let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".config"));
    let cache_dir = dirs::cache_dir().unwrap_or_else(|| PathBuf::from(".cache"));

    let keyfile = keyfile.unwrap_or_else(|| config_dir.join("tatu/identity.key"));

    let handles_path = std::env::var("TATU_HANDLE_CACHE")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| cache_dir.join("tatu/handles"));

    let known_servers_path = std::env::var("TATU_KNOWN_SERVERS")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir.join("tatu/known-servers.pin"));

    (keyfile, handles_path, known_servers_path)
}

impl Runtime {
    fn load(args: &RunArgs) -> anyhow::Result<Self> {
        let (keyfile, handles_path, known_servers_path) = resolve_paths(args.keyfile.clone());

        let (identity, recovery_phrase) = TatuKey::load_or_generate(&keyfile, None)?;

        let identity = Arc::new(identity);
        let keychain = Keychain::new(identity, &handles_path, &known_servers_path)?;

        let skin = args
            .skin
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?
            .map(prob_json)
            .transpose()?
            .map(Into::into);

        Ok(Self {
            dest_addr: args.dest_addr.clone(),
            skin,
            keychain: Arc::new(keychain),
            recovery_phrase: Mutex::new(recovery_phrase),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli: Cli = argh::from_env();

    match cli.mode {
        Mode::Recover(recover_args) => {
            run_recovery(recover_args.keyfile)?;
        }
        Mode::Run(run_args) => {
            run_proxy(run_args).await?;
        }
    }

    Ok(())
}

fn run_recovery(keyfile: Option<PathBuf>) -> anyhow::Result<()> {
    let (keyfile, _, _) = resolve_paths(keyfile);

    let recovery_phrase = recovery_prompt()?;
    let (identity, _) = TatuKey::load_or_generate(&keyfile, Some(&recovery_phrase))?;

    let uuid = RemoteTatuKey::from_x_pub(identity.x_pub()).uuid();

    eprintln!(
        "recovered identity (uuid={}) to keyfile={}",
        uuid.as_hyphenated(),
        keyfile.display()
    );
    Ok(())
}

async fn run_proxy(args: RunArgs) -> anyhow::Result<()> {
    let (keyfile, _, _) = resolve_paths(args.keyfile.clone());
    let runtime = Runtime::load(&args)?;
    let runtime = Arc::new(runtime);

    let version = format!(
        "client v{} ({}/{}{})",
        build::PKG_VERSION,
        build::BRANCH,
        build::SHORT_COMMIT,
        if build::GIT_CLEAN { "" } else { "-dirty" }
    );

    let uuid = RemoteTatuKey::from_x_pub(runtime.keychain.identity.x_pub()).uuid();

    print_banner(&[
        ("version", &version as &dyn std::fmt::Display),
        ("proxy", &args.listen_addr),
        ("destination", &runtime.dest_addr),
        ("keyfile", &keyfile.display()),
        ("uuid", &uuid.as_hyphenated()),
    ]);

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let recovery_phrase = runtime.recovery_phrase.lock().unwrap().take();
    if let Some(phrase) = recovery_phrase {
        tracing::warn!("new identity generated");
        tracing::warn!("recovery phrase: {}", phrase);
        tracing::warn!(
            "write it down NOW. without it OR your keyfile, you won't be able to recover your identity!"
        );
        tracing::warn!("this will only be shown again in-game (unless you restart the program)\n");
    }

    let listener = TcpListener::bind(&args.listen_addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, runtime).await {
                tracing::error!("Connection error: {e}");
            }
        });
    }
}

fn prob_json(s: String) -> anyhow::Result<String> {
    let t = s.trim();

    if !t.starts_with('{') && !t.starts_with('[') {
        anyhow::bail!("Not JSON given");
    }
    if !t.ends_with('}') && !t.ends_with(']') {
        anyhow::bail!("JSON cut off");
    }
    if t.contains('{') && t.contains(':') && !t.contains("\":") {
        anyhow::bail!("Given SNBT, not JSON (tip: quote the fields)");
    }

    Ok(s)
}

fn recovery_prompt() -> anyhow::Result<RecoveryPhrase> {
    use std::io::{self, Write};

    eprintln!("Enter your 12-word recovery phrase:");
    eprint!("> ");
    io::stderr().flush()?;

    let input = rpassword::read_password()?;

    let (phrase, errors) = RecoveryPhrase::parse(&input)?;
    if errors > 0 {
        tracing::warn!("corrected {} errors.", errors);
    }

    Ok(phrase)
}

async fn handle_client(stream: TcpStream, rt: Arc<Runtime>) -> anyhow::Result<()> {
    use azalea_protocol::{connect::Connection, packets::ClientIntention};

    let mut conn = Connection::wrap(stream);

    let handshake: ServerboundHandshakePacket = match conn.read().await {
        Ok(handshake @ ServerboundHandshakePacket::Intention(_)) => handshake,
        Err(_) => anyhow::bail!("Failed to read handshake"),
    };

    let intention = match &handshake {
        ServerboundHandshakePacket::Intention(i) => &i.intention,
    };

    match intention {
        ClientIntention::Status => {
            return handle_ping(conn, &rt.dest_addr).await;
        }
        ClientIntention::Login => {}
        _ => anyhow::bail!("Unsupported intention type"),
    }

    let (mc_conn, nick) = finish_login_handshake(conn).await?;
    tracing::info!(nick = %nick, server = %rt.dest_addr, "connecting");

    let phrase = rt.recovery_phrase.lock().unwrap().take();
    if let Some(phrase) = phrase {
        let keychain = Arc::clone(&rt.keychain);
        let nick_clone = nick.clone();
        tokio::spawn(async move {
            let _ = keychain.ensure_handle(&nick_clone).await;
        });

        // NOTE: Minecraft logs chat messages, but not server disconnect messages

        send_disconnect(
            mc_conn,
            &format!(
                "§aNew identity created!
§6Write down your recovery phrase NOW:

§e{}

§7Without this phrase, you won't be able to
recover your account on a new device.
This will only be shown once.

§6Reconnect when you're ready.",
                phrase
                    .to_string()
                    .split('-')
                    .collect::<Vec<_>>()
                    .chunks(6)
                    .map(|chunk| chunk.join("-"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .await?;
        return Ok(());
    }

    let handle_claim = match rt.keychain.ensure_handle(&nick).await {
        Ok(claim) => claim,
        Err(keychain::LoadHandleError::NeedsMining) => {
            send_disconnect(
                mc_conn,
                "§6Mining your handle discriminator...

§7This should take about 40 seconds.
§7Reconnect after it's done.",
            )
            .await?;
            return Ok(());
        }
        Err(keychain::LoadHandleError::Io(e)) => return Err(e.into()),
    };

    let tcp_stream = TcpStream::connect(&rt.dest_addr).await?;
    tcp_stream.set_nodelay(true)?;

    let x_key = rt.keychain.identity.x_key();
    let mut secure_pipe = NoisePipe::connect(tcp_stream, &x_key).await?;

    let server_key = RemoteTatuKey::from_x_pub(secure_pipe.remote_public_key()?);

    let tofu_message = {
        match rt.keychain.id_server(&rt.dest_addr, &server_key) {
            Ok(()) => {
                tracing::info!(server = %rt.dest_addr, key = %server_key, "known");
                None
            }
            Err(keychain::PinError::NotKnown) => {
                tracing::warn!(server = %rt.dest_addr, key = %server_key, "new server, pinning");
                rt.keychain.pin_server(rt.dest_addr.clone(), server_key)?;
                tracing::info!("tip: verify this key through a trusted channel!");

                fn chunked_key(key: String) -> String {
                    key.chars()
                        .collect::<Vec<_>>()
                        .chunks(11)
                        .map(|c| c.iter().collect::<String>())
                        .collect::<Vec<_>>()
                        .join(" ")
                }

                Some(format!(
                    "§6tatu: new server saved:\n§e{}
§6tatu: this should match the key outside the game!",
                    chunked_key(server_key.to_string())
                ))
            }
            Err(keychain::PinError::Mismatch) => {
                send_disconnect(
                    mc_conn,
                    "§cPossible server impersonation!
§7This server's identity is different from before.

It may have changed owners, lost its keys,
or recovered from a breach—or you are
being wiretapped.

§6If you know why it happened, delete it from
tatu-servers.pin",
                )
                .await?;
                anyhow::bail!("Server key mismatch! Potential MITM attack detected");
            }
        }
    };

    let auth_msg = AuthMessage {
        handle_claim,
        skin: rt.skin.as_deref().map(String::from),
    };

    secure_pipe
        .send(Bytes::from(rmp_serde::to_vec(&auth_msg)?))
        .await?;

    let handshake_bytes = protocol::write::serialize_packet(&handshake)?;
    secure_pipe.send(Bytes::from(handshake_bytes)).await?;

    tracing::info!("connected");

    let (mc_conn, secure_pipe) = await_play(mc_conn, secure_pipe).await?;
    let (mc_read, mut mc_write) = mc_conn;

    if let Some(message) = tofu_message
        && let Err(e) = send_message(&mut mc_write, &message).await
    {
        tracing::warn!("Failed to show fingerprint: {e}");
    }

    let result = forward_messages((mc_read, mc_write), secure_pipe).await;
    tracing::info!(server = %rt.dest_addr, "disconnected");

    result
}

async fn send_message(
    mc_write: &mut azalea_protocol::connect::RawWriteConnection,
    message: &str,
) -> anyhow::Result<()> {
    use azalea_chat::FormattedText;
    use protocol::packets::game::c_system_chat::ClientboundSystemChat;

    let ft: FormattedText = message.into();
    let packet = ClientboundGamePacket::SystemChat(ClientboundSystemChat {
        content: ft,
        overlay: false,
    });

    let bytes = serialize_packet(&packet)?;
    mc_write.write(&bytes).await?;
    Ok(())
}

async fn send_disconnect(mc_conn: MCReadWriteConn, message: &str) -> anyhow::Result<()> {
    use azalea_chat::FormattedText;
    use protocol::packets::login::{
        ClientboundLoginPacket, c_login_disconnect::ClientboundLoginDisconnect,
    };
    let (_mc_read, mut mc_write) = mc_conn;

    let ft: FormattedText = message.into();
    let disconnect_packet =
        ClientboundLoginPacket::LoginDisconnect(ClientboundLoginDisconnect { reason: ft });

    let bytes = serialize_packet(&disconnect_packet)?;
    mc_write.write(&bytes).await?;
    Ok(())
}

async fn finish_login_handshake(
    conn: azalea_protocol::connect::Connection<
        ServerboundHandshakePacket,
        azalea_protocol::packets::handshake::ClientboundHandshakePacket,
    >,
) -> anyhow::Result<(MCReadWriteConn, String)> {
    use protocol::packets::login::ServerboundLoginPacket;

    let mut conn = conn.login();

    let hello = loop {
        match conn.read().await {
            Ok(ServerboundLoginPacket::Hello(h)) => break h,
            Ok(_) => continue,
            Err(e) if matches!(*e, ReadPacketError::ConnectionClosed) => {
                anyhow::bail!("Connection closed during login")
            }
            Err(e) => return Err(e.into()),
        }
    };

    let mut nick = hello.name.clone();
    nick.truncate(MAX_NICK_LENGTH);

    let mc_conn = conn.into_split_raw();
    Ok((mc_conn, nick))
}

async fn handle_ping(
    conn: azalea_protocol::connect::Connection<
        ServerboundHandshakePacket,
        azalea_protocol::packets::handshake::ClientboundHandshakePacket,
    >,
    server_addr: &str,
) -> anyhow::Result<()> {
    use azalea_protocol::packets::status::{
        ClientboundStatusPacket, ServerboundStatusPacket,
        c_pong_response::ClientboundPongResponse,
        c_status_response::{ClientboundStatusResponse, Players, Version},
    };

    let mut status_conn = conn.status();
    let description = format!("§7{}\n§6A Tatu server", server_addr);

    // Expect status request, send static response
    if let Ok(ServerboundStatusPacket::StatusRequest(_)) = status_conn.read().await {
        status_conn
            .write(ClientboundStatusPacket::StatusResponse(
                ClientboundStatusResponse {
                    description: description.into(),
                    favicon: None,
                    players: Players {
                        max: 0,
                        online: 0,
                        sample: vec![],
                    },
                    version: Version {
                        name: "Tatu Proxy".to_string(),
                        protocol: azalea_protocol::packets::PROTOCOL_VERSION,
                    },
                    enforces_secure_chat: Some(false),
                },
            ))
            .await?;
    }

    // Expect ping request, send pong response
    if let Ok(ServerboundStatusPacket::PingRequest(ping)) = status_conn.read().await {
        status_conn
            .write(ClientboundStatusPacket::PongResponse(
                ClientboundPongResponse { time: ping.time },
            ))
            .await?;
    }

    Ok(())
}

async fn await_play(
    mc_conn: MCReadWriteConn,
    proxy: NoisePipe<TcpStream>,
) -> anyhow::Result<(MCReadWriteConn, NoisePipe<TcpStream>)> {
    let (mut mc_read, mut mc_write) = mc_conn;
    use protocol::{
        packets::config::{ClientboundConfigPacket, ServerboundConfigPacket},
        read::deserialize_packet,
    };

    enum State {
        WaitingForServerConfig,
        WaitingForClientConfig,
        Ready,
    }

    let (mut proxy_sink, mut proxy_stream) = proxy.split();
    let mut state = State::WaitingForServerConfig;

    loop {
        tokio::select! {
            bytes = mc_read.read() => {
                let bytes = bytes?;

                if let State::WaitingForClientConfig = state {
                    let mut cursor = std::io::Cursor::new(&bytes[..]);
                    if let Ok(ServerboundConfigPacket::FinishConfiguration(_)) =
                        deserialize_packet::<ServerboundConfigPacket>(&mut cursor)
                    {
                        state = State::Ready;
                    }
                }

                proxy_sink.send(Bytes::from(bytes)).await?;
                proxy_sink.flush().await?;
            }

            proxy_msg = proxy_stream.next() => {
                let bytes = match proxy_msg {
                    Some(Ok(bytes)) => bytes,
                    Some(Err(e)) => return Err(e.into()),
                    None => anyhow::bail!("Proxy connection closed before reaching game state"),
                };

                let mut cursor = std::io::Cursor::new(&bytes[..]);
                state = match state {
                    State::WaitingForServerConfig => {
                        match deserialize_packet::<ClientboundConfigPacket>(&mut cursor) {
                            Ok(ClientboundConfigPacket::FinishConfiguration(_)) => State::WaitingForClientConfig,
                            _ => State::WaitingForServerConfig,
                        }
                    }
                    State::Ready => {
                        if deserialize_packet::<ClientboundGamePacket>(&mut cursor).is_ok() {
                            mc_write.write(&bytes).await?;
                            return Ok(((mc_read, mc_write), proxy_sink.reunite(proxy_stream)?));
                        }
                        State::Ready
                    }
                    s => s,
                };

                mc_write.write(&bytes).await?;
            }
        }
    }
}

async fn forward_messages(
    mc_conn: MCReadWriteConn,
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
                    Err(e) if matches!(*e, ReadPacketError::ConnectionClosed) => {
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
