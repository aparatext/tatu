mod keychain;

use argh::FromArgs;
use shadow_rs::shadow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use keychain::Keychain;
use tatu_lib::{
    keys::{RecoveryPhrase, RemoteTatuKey, TatuKey},
    minecraft::Handshake,
    model::AuthMessage,
    noise::NoisePipe,
    framing::write_frame,
};

shadow!(build);

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
/// Connect to a tatu server through local proxy
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
    keyphrase: Mutex<Option<RecoveryPhrase>>,
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

        let (identity, keyphrase) = TatuKey::load_or_generate(&keyfile, None)?;

        let identity = Arc::new(identity);
        let keychain = Keychain::new(identity, &handles_path, &known_servers_path)?;

        let skin = args
            .skin
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?
            .map(ensure_json)
            .transpose()?
            .map(Into::into);

        Ok(Self {
            dest_addr: args.dest_addr.clone(),
            skin,
            keychain: Arc::new(keychain),
            keyphrase: Mutex::new(keyphrase),
        })
    }
}

// Probabalistic JSON check
// We don't need to parse it anywhere and syntax will fall open in Minecraft.
// This is just a user affordance.
fn ensure_json(s: String) -> anyhow::Result<String> {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli: Cli = argh::from_env();

    match cli.mode {
        Mode::Recover(recover_args) => run_recovery(recover_args.keyfile)?,
        Mode::Run(run_args) => run_proxy(run_args).await?,
    }

    Ok(())
}

fn run_recovery(keyfile: Option<PathBuf>) -> anyhow::Result<()> {
    let (keyfile, _, _) = resolve_paths(keyfile);

    let keyphrase = recovery_prompt()?;
    let (identity, _) = TatuKey::load_or_generate(&keyfile, Some(&keyphrase))?;

    eprintln!(
        "recovered identity (uuid={}) to keyfile={}",
        identity.uuid().as_hyphenated(),
        keyfile.display()
    );
    Ok(())
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

async fn run_proxy(args: RunArgs) -> anyhow::Result<()> {
    let (keyfile, _, _) = resolve_paths(args.keyfile.clone());
    let runtime = Arc::new(Runtime::load(&args)?);

    eprintln!(
        "version: client v{} ({}/{}{})",
        build::PKG_VERSION,
        build::BRANCH,
        build::SHORT_COMMIT,
        if build::GIT_CLEAN { "" } else { "-dirty" }
    );
    eprintln!("proxy: {}", args.listen_addr);
    eprintln!("destination: {}", runtime.dest_addr);
    eprintln!("keyfile: {}", keyfile.display());
    eprintln!(
        "uuid: {}\n",
        runtime.keychain.identity.uuid().as_hyphenated()
    );

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let keyphrase = runtime.keyphrase.lock().unwrap().take();
    if let Some(phrase) = keyphrase {
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

async fn handle_client(stream: TcpStream, rt: Arc<Runtime>) -> anyhow::Result<()> {
    let handshake = Handshake::accept(stream).await?;

    if handshake.is_status() {
        return Ok(handshake
            .handle_status(format!("§7{}\n§6A Tatu server", rt.dest_addr))
            .await?);
    }

    let (mut mc, mut nick) = handshake.into_login().await?;
    nick.truncate(MAX_NICK_LENGTH);
    tracing::info!(nick = %nick, server = %rt.dest_addr, "connecting");

    let phrase = rt.keyphrase.lock().unwrap().take();
    if let Some(phrase) = phrase {
        let keychain = Arc::clone(&rt.keychain);
        let nick = nick.clone();
        tokio::spawn(async move {
            let _ = keychain.ensure_handle(&nick).await;
        });

        mc.send_disconnect(&format!(
            "§aNew identity created!
§6Write down your recovery phrase NOW:\n\n§e{:#}

§7Without this phrase, you won't be able to
recover your account on a new device.
This will only be shown once.

§6Reconnect when you're ready.",
            phrase
        ))
        .await?;
        return Ok(());
    }

    let handle_proof = match rt.keychain.ensure_handle(&nick).await {
        Ok(claim) => claim,
        Err(keychain::LoadHandleError::NeedsMining) => {
            mc.send_disconnect(
                "§6Mining your handle discriminator...

§7This should take about 40 seconds.
§7Reconnect after it's done.",
            )
            .await?;
            return Ok(());
        }
        Err(keychain::LoadHandleError::Io(e)) => return Err(e.into()),
    };

    let tatu_stream = TcpStream::connect(&rt.dest_addr).await?;
    tatu_stream.set_nodelay(true)?;

    let x_key = rt.keychain.identity.x_key();
    let mut secure_pipe = NoisePipe::connect(tatu_stream, &x_key).await?;

    let server_key = RemoteTatuKey::from_x_pub(secure_pipe.remote_public_key()?);

    match rt.keychain.id_server(&rt.dest_addr, &server_key) {
        Ok(()) => {
            tracing::info!(server = %rt.dest_addr, key = %server_key, "known");
        }
        Err(keychain::PinError::NotKnown) => {
            tracing::warn!(server = %rt.dest_addr, key = %server_key, "new server, pinning");
            rt.keychain.pin_server(rt.dest_addr.clone(), server_key)?;
            tracing::info!("tip: verify this key through a trusted channel!");

            mc.queue_message(format!(
                "§6tatu: new server saved:\n§e{:#}
§6tatu: this should match the key outside the game!",
                server_key
            ))?;
        }
        Err(keychain::PinError::Mismatch) => {
            mc.send_disconnect(
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
    };

    let auth_msg = AuthMessage {
        handle_proof,
        skin: rt.skin.as_deref().map(String::from),
    };

    write_frame(&mut secure_pipe, &rmp_serde::to_vec(&auth_msg)?).await?;
    write_frame(&mut secure_pipe, &mc.handshake_bytes()?).await?;
    secure_pipe.flush().await?;
    let bridge = mc.into_bridge();

    tracing::info!("connected");
    let result = bridge.forward(secure_pipe).await;
    tracing::info!(server = %rt.dest_addr, "disconnected");

    result.map_err(Into::into)
}
