mod keychain;

use bytes::Bytes;
use clap::Parser;
use futures::{SinkExt, StreamExt};
use keychain::Keychain;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tatu_common::keys::{RemoteTatuKey, TatuKey};
use tatu_common::noise::NoisePipe;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const MAX_NICK_LENGTH: usize = 7;

#[derive(Parser)]
#[command(about = "Tatu client proxy")]
struct Args {
    #[arg(default_value = "127.0.0.1:25519")]
    proxy_addr: String,

    #[arg(long, default_value = "127.0.0.1:25565")]
    listen_addr: String,

    #[arg(long = "skin")]
    skin_path: Option<PathBuf>,

    #[arg(long = "key", env = "TATU_KEY", default_value = "tatu-id.key")]
    key_path: PathBuf,

    #[arg(
        long = "handles",
        env = "TATU_HANDLE_CACHE",
        default_value = "tatu-handles"
    )]
    handles_path: PathBuf,

    #[arg(
        long = "known-servers",
        env = "TATU_KNOWN_SERVERS",
        default_value = "tatu-servers.pin"
    )]
    known_servers_path: PathBuf,
}

struct Runtime {
    proxy_addr: String,
    skin: Option<Arc<str>>,
    keychain: Arc<Keychain>,
    nick_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl Runtime {
    fn load(args: &Args) -> anyhow::Result<Self> {
        let identity = Arc::new(TatuKey::load_or_generate(&args.key_path)?);

        let skin = args
            .skin_path
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?
            .map(prob_json)
            .transpose()?
            .map(Into::into);

        let keychain = Keychain::new(identity, &args.handles_path, &args.known_servers_path)?;

        Ok(Self {
            proxy_addr: args.proxy_addr.clone(),
            skin,
            keychain: Arc::new(keychain),
            nick_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen_addr).await?;
    let runtime = Arc::new(Runtime::load(&args)?);

    tracing::info!(
        "Client proxy listening on {}, forwarding to {}",
        args.listen_addr,
        runtime.proxy_addr
    );

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

async fn inject_message(
    mc_write: &mut azalea::protocol::connect::RawWriteConnection,
    message: &str,
) -> anyhow::Result<()> {
    use azalea::FormattedText;
    use azalea::protocol::{
        packets::game::{ClientboundGamePacket, c_system_chat::ClientboundSystemChat},
        write::serialize_packet,
    };

    let formatted_text: FormattedText = message.into();
    let game_packet = ClientboundGamePacket::SystemChat(ClientboundSystemChat {
        content: formatted_text,
        overlay: false,
    });
    let bytes = serialize_packet(&game_packet)?;
    mc_write.write(&bytes).await?;
    Ok(())
}

async fn send_disconnect(
    mc_write: &mut azalea::protocol::connect::RawWriteConnection,
    message: &str,
) -> anyhow::Result<()> {
    use azalea::FormattedText;
    use azalea::protocol::{
        packets::login::{ClientboundLoginPacket, c_login_disconnect::ClientboundLoginDisconnect},
        write::serialize_packet,
    };

    let formatted_text: FormattedText = message.into();
    let disconnect_packet = ClientboundLoginPacket::LoginDisconnect(ClientboundLoginDisconnect {
        reason: formatted_text,
    });
    let bytes = serialize_packet(&disconnect_packet)?;
    mc_write.write(&bytes).await?;
    Ok(())
}

async fn handle_client(stream: TcpStream, rt: Arc<Runtime>) -> anyhow::Result<()> {
    let (mc_read, mut mc_write, nick) = read_mc_login(stream).await?;
    tracing::info!("Connecting as {nick}");

    let nick_lock = {
        let mut locks = rt.nick_locks.lock().await;
        locks
            .entry(nick.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };

    let _guard = match nick_lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            send_disconnect(
                &mut mc_write,
                "§6Mining your handle discriminator...

§7Another connection is mining this nick.
§7Reconnect in a moment.",
            )
            .await?;
            drop(mc_read);
            drop(mc_write);
            return Ok(());
        }
    };

    let handle_claim = match rt.keychain.load_handle(&nick) {
        Ok(claim) => claim,
        Err(keychain::LoadHandleError::NeedsMining) => {
            tracing::info!("Handle not cached for '{}', mining...", nick);
            send_disconnect(
                &mut mc_write,
                "§6Mining your handle discriminator...

§7This should take 40 seconds, once per nick.
§7Reconnect after it's done.",
            )
            .await?;

            drop(mc_read);
            drop(mc_write);

            let keychain = Arc::clone(&rt.keychain);
            let nick_clone = nick.clone();
            tokio::task::spawn_blocking(move || keychain.mine_handle(&nick_clone)).await??;

            tracing::info!("Handle mined for '{}'", nick);
            return Ok(());
        }
        Err(keychain::LoadHandleError::Io(e)) => return Err(e.into()),
    };

    let tcp_stream = TcpStream::connect(&rt.proxy_addr).await?;
    tcp_stream.set_nodelay(true)?;

    let x_key = rt.keychain.identity.x_key();
    let mut secure_pipe = NoisePipe::connect(tcp_stream, &x_key).await?;

    let server_key = RemoteTatuKey::from_x_pub(secure_pipe.remote_public_key()?);

    let chat_message = {
        match rt.keychain.id_server(&rt.proxy_addr, &server_key) {
            Ok(()) => {
                tracing::info!("Server key verified");
                None
            }
            Err(keychain::PinError::NotKnown) => {
                tracing::warn!("Server not known, pinning key: {server_key}");
                rt.keychain.pin_server(rt.proxy_addr.clone(), server_key)?;
                tracing::info!("Verify this key through a trusted channel!");

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
§6tatu: it should match the key outside the game!",
                    chunked_key(server_key.to_string())
                ))
            }
            Err(keychain::PinError::Mismatch) => {
                send_disconnect(
                    &mut mc_write,
                    "§cPossible server impersonation!
§7This server's identity is different from before.

It may have changed owners, lost its keys,
or recovered from a breach—or you are
being wiretapped.

§6If you know why it happened, delete it from
tatu-servers.pin",
                )
                .await?;
                drop(mc_read);
                drop(mc_write);
                anyhow::bail!("Server key mismatch! Potential MITM attack detected");
            }
        }
    };

    let auth_msg = tatu_common::model::AuthMessage {
        handle_claim,
        skin: rt.skin.as_deref().map(String::from),
    };

    secure_pipe
        .send(Bytes::from(rmp_serde::to_vec(&auth_msg)?))
        .await?;

    tracing::info!("Connected to proxy server");

    let (mc_read, mut mc_write, secure_pipe) =
        wait_for_game_state(mc_read, mc_write, secure_pipe).await?;

    if let Some(message) = chat_message
        && let Err(e) = inject_message(&mut mc_write, &message).await
    {
        tracing::warn!("Failed to inject chat message: {e}");
    }

    let result = forward_messages(mc_read, mc_write, secure_pipe).await;
    tracing::info!("Disconnected");

    result
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

async fn read_mc_login(
    stream: TcpStream,
) -> anyhow::Result<(
    azalea::protocol::connect::RawReadConnection,
    azalea::protocol::connect::RawWriteConnection,
    String,
)> {
    use azalea::protocol::{
        connect::Connection,
        packets::{handshake::ServerboundHandshakePacket, login::ServerboundLoginPacket},
        read::ReadPacketError,
    };

    let mut conn = Connection::wrap(stream);

    match conn.read().await {
        Ok(ServerboundHandshakePacket::Intention(_)) => {}
        Err(_) => anyhow::bail!("Failed to read handshake"),
    }

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

    // Return raw connections immediately - can't transition to game state
    // because the client hasn't received login success yet (that comes from the real server)
    let (read, write) = conn.into_split_raw();
    Ok((read, write, nick))
}

/// Wait for the Minecraft client and server to complete protocol negotiation
/// and reach game state. Returns the connections when ready for game packets.
async fn wait_for_game_state(
    mut mc_read: azalea::protocol::connect::RawReadConnection,
    mut mc_write: azalea::protocol::connect::RawWriteConnection,
    proxy: NoisePipe<TcpStream>,
) -> anyhow::Result<(
    azalea::protocol::connect::RawReadConnection,
    azalea::protocol::connect::RawWriteConnection,
    NoisePipe<TcpStream>,
)> {
    let (mut proxy_sink, mut proxy_stream) = proxy.split();

    let config_finished = wait_for_login(
        &mut mc_read,
        &mut mc_write,
        &mut proxy_sink,
        &mut proxy_stream,
    )
    .await?;

    if config_finished {
        wait_for_game_start(
            &mut mc_read,
            &mut mc_write,
            &mut proxy_sink,
            &mut proxy_stream,
        )
        .await?;
    }

    let proxy = proxy_sink.reunite(proxy_stream)?;
    Ok((mc_read, mc_write, proxy))
}

/// Transparent bidirectional forwarding between Minecraft client and proxy server
async fn forward_messages(
    mut mc_read: azalea::protocol::connect::RawReadConnection,
    mut mc_write: azalea::protocol::connect::RawWriteConnection,
    proxy: NoisePipe<TcpStream>,
) -> anyhow::Result<()> {
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

async fn wait_for_login(
    mc_read: &mut azalea::protocol::connect::RawReadConnection,
    mc_write: &mut azalea::protocol::connect::RawWriteConnection,
    proxy_sink: &mut futures::stream::SplitSink<NoisePipe<TcpStream>, Bytes>,
    proxy_stream: &mut futures::stream::SplitStream<NoisePipe<TcpStream>>,
) -> anyhow::Result<bool> {
    use azalea::protocol::{
        packets::{
            config::{ClientboundConfigPacket, ServerboundConfigPacket},
            login::{ClientboundLoginPacket, ServerboundLoginPacket},
        },
        read::deserialize_packet,
    };

    let mut login_finished_sent = false;
    let mut in_config_phase = false;
    let mut config_finished_sent = false;

    loop {
        tokio::select! {
            mc_msg = mc_read.read() => {
                match mc_msg {
                    Ok(bytes) => {
                        if login_finished_sent && !in_config_phase {
                            let mut cursor = std::io::Cursor::new(&bytes[..]);
                            if let Ok(packet) = deserialize_packet::<ServerboundLoginPacket>(&mut cursor)
                                && matches!(packet, ServerboundLoginPacket::LoginAcknowledged(_))
                            {
                                proxy_sink.send(Bytes::from(bytes)).await?;
                                proxy_sink.flush().await?;
                                in_config_phase = true;
                                continue;
                            }
                        }

                        if in_config_phase && config_finished_sent {
                            let mut cursor = std::io::Cursor::new(&bytes[..]);
                            if let Ok(packet) = deserialize_packet::<ServerboundConfigPacket>(&mut cursor)
                                && matches!(packet, ServerboundConfigPacket::FinishConfiguration(_))
                            {
                                proxy_sink.send(Bytes::from(bytes)).await?;
                                proxy_sink.flush().await?;
                                return Ok(true);
                            }
                        }

                        proxy_sink.send(Bytes::from(bytes)).await?;
                        proxy_sink.flush().await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            proxy_msg = proxy_stream.next() => {
                match proxy_msg {
                    Some(Ok(bytes)) => {
                        if !login_finished_sent {
                            let mut cursor = std::io::Cursor::new(&bytes[..]);
                            if let Ok(packet) = deserialize_packet::<ClientboundLoginPacket>(&mut cursor)
                                && matches!(packet, ClientboundLoginPacket::LoginFinished(_))
                            {
                                mc_write.write(&bytes).await?;
                                login_finished_sent = true;
                                continue;
                            }
                        }

                        if in_config_phase && !config_finished_sent {
                            let mut cursor = std::io::Cursor::new(&bytes[..]);
                            if let Ok(packet) = deserialize_packet::<ClientboundConfigPacket>(&mut cursor)
                                && matches!(packet, ClientboundConfigPacket::FinishConfiguration(_))
                            {
                                mc_write.write(&bytes).await?;
                                config_finished_sent = true;
                                continue;
                            }
                        }

                        mc_write.write(&bytes).await?;
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(false),
                }
            }
        }
    }
}

async fn wait_for_game_start(
    mc_read: &mut azalea::protocol::connect::RawReadConnection,
    mc_write: &mut azalea::protocol::connect::RawWriteConnection,
    proxy_sink: &mut futures::stream::SplitSink<NoisePipe<TcpStream>, Bytes>,
    proxy_stream: &mut futures::stream::SplitStream<NoisePipe<TcpStream>>,
) -> anyhow::Result<bool> {
    use azalea::protocol::{packets::game::ClientboundGamePacket, read::deserialize_packet};

    loop {
        tokio::select! {
            mc_msg = mc_read.read() => {
                match mc_msg {
                    Ok(bytes) => {
                        proxy_sink.send(Bytes::from(bytes)).await?;
                        proxy_sink.flush().await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            proxy_msg = proxy_stream.next() => {
                match proxy_msg {
                    Some(Ok(bytes)) => {
                        let mut cursor = std::io::Cursor::new(&bytes[..]);
                        if deserialize_packet::<ClientboundGamePacket>(&mut cursor).is_ok() {
                            mc_write.write(&bytes).await?;
                            return Ok(true);
                        }

                        mc_write.write(&bytes).await?;
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(false),
                }
            }
        }
    }
}
