use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tatu_lib::keys::{RemoteTatuKey, TatuKey};
use tatu_lib::model::HandleProof;
use thiserror::Error;
use tokio::sync::{Mutex, OnceCell};

#[derive(Debug, Error)]
pub enum PinError {
    #[error("Server not known")]
    NotKnown,
    #[error("Server key mismatch")]
    Mismatch,
}

#[derive(Debug, Error)]
pub enum LoadHandleError {
    #[error("Handle needs to be mined")]
    NeedsMining,
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

pub struct Keychain {
    pub identity: Arc<TatuKey>,
    handles_dir: PathBuf,
    known_servers: RwLock<HashMap<String, RemoteTatuKey>>,
    servers_path: PathBuf,
    mining_cells: Mutex<HashMap<String, Arc<OnceCell<()>>>>,
}

impl Keychain {
    pub fn new(
        identity: Arc<TatuKey>,
        handles_dir: impl Into<PathBuf>,
        servers_path: impl Into<PathBuf>,
    ) -> io::Result<Self> {
        let servers_path = servers_path.into();
        let known_servers = Self::load_pins(&servers_path)?;

        Ok(Keychain {
            identity,
            known_servers: RwLock::new(known_servers),
            handles_dir: handles_dir.into(),
            servers_path,
            mining_cells: Mutex::new(HashMap::new()),
        })
    }

    fn load_pins(path: &Path) -> io::Result<HashMap<String, RemoteTatuKey>> {
        let mut pins = HashMap::new();
        if !path.exists() {
            return Ok(pins);
        }

        let content = fs::read_to_string(path)?;

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Invalid pin format on line {}: expected '<hostname> <base58-pubkey>'",
                        line_num + 1
                    ),
                ));
            }

            let hostname = parts[0].to_string();
            let pubkey = RemoteTatuKey::from_base58(parts[1]).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid key on line {}: {}", line_num + 1, e),
                )
            })?;

            pins.insert(hostname, pubkey);
        }

        Ok(pins)
    }

    fn save_pins(&self) -> io::Result<()> {
        let servers = self.known_servers.read().unwrap();
        let mut lines: Vec<String> = servers
            .iter()
            .map(|(host, key)| format!("{} {}", host, key))
            .collect();

        lines.sort();
        let content = lines.join("\n") + "\n";

        if let Some(parent) = self.servers_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.servers_path, content)
    }

    pub fn load_handle(&self, nick: &str) -> Result<HandleProof, LoadHandleError> {
        let uuid_dir = self.handles_dir.join(self.identity.uuid().to_string());
        let file_path = uuid_dir.join(format!("{}.nick", nick));

        if !file_path.exists() {
            return Err(LoadHandleError::NeedsMining);
        }

        let data = fs::read(&file_path)?;
        let claim = match rmp_serde::from_slice::<HandleProof>(&data) {
            Ok(claim) => claim,
            Err(e) => {
                tracing::warn!(nick = %nick, error = %e, "corrupt handle claim, remining");
                let _ = fs::remove_file(&file_path);
                return Err(LoadHandleError::NeedsMining);
            }
        };

        let public_key = self.identity.x_pub();
        if let Err(e) = claim.verify(&public_key) {
            tracing::warn!(nick = %nick, error = %e, "handle claim invalid. remining...");
            let _ = fs::remove_file(&file_path);
            return Err(LoadHandleError::NeedsMining);
        }

        Ok(claim)
    }

    pub async fn ensure_handle(
        self: &Arc<Self>,
        nick: &str,
    ) -> Result<HandleProof, LoadHandleError> {
        match self.load_handle(nick) {
            Ok(claim) => return Ok(claim),
            Err(LoadHandleError::Io(e)) => return Err(LoadHandleError::Io(e)),
            Err(LoadHandleError::NeedsMining) => {}
        }

        let cell = {
            let mut cells = self.mining_cells.lock().await;
            cells
                .entry(nick.to_owned())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };

        if cell.set(()).is_ok() {
            let keychain = Arc::clone(self);
            let nick_clone = nick.to_string();

            tokio::task::spawn_blocking(move || {
                if let Err(e) = keychain.mine_handle(&nick_clone) {
                    tracing::error!("Failed to mine handle for '{}': {}", nick_clone, e);
                    // Remove the cell so next connection can retry
                    let handle = tokio::runtime::Handle::current();
                    handle.block_on(async {
                        let mut cells = keychain.mining_cells.lock().await;
                        cells.remove(&nick_clone);
                    });
                }
            });
        }

        Err(LoadHandleError::NeedsMining)
    }

    pub fn mine_handle(&self, nick: &str) -> io::Result<HandleProof> {
        tracing::info!(nick = %nick, "mining handle");

        let claim = HandleProof::mine(nick.to_string(), &self.identity.ed_key())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let data =
            rmp_serde::to_vec(&claim).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let uuid_dir = self.handles_dir.join(self.identity.uuid().to_string());
        fs::create_dir_all(&uuid_dir)?;
        fs::write(uuid_dir.join(format!("{}.nick", nick)), data)?;

        tracing::info!(nick = %nick, "handle mined");
        Ok(claim)
    }

    pub fn id_server(&self, host: &str, key: &RemoteTatuKey) -> Result<(), PinError> {
        let servers = self.known_servers.read().unwrap();
        match servers.get(host) {
            None => Err(PinError::NotKnown),
            Some(pinned_key) => {
                if pinned_key == key {
                    Ok(())
                } else {
                    Err(PinError::Mismatch)
                }
            }
        }
    }

    pub fn pin_server(&self, host: String, key: RemoteTatuKey) -> io::Result<()> {
        let mut servers = self.known_servers.write().unwrap();
        servers.insert(host, key);
        drop(servers); // Release write lock before save_pins
        self.save_pins()
    }
}
