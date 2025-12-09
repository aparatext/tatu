use base58::{FromBase58, ToBase58};
use ed25519::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;
use x25519::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TatuKey {
    #[serde(with = "serde_bytes")]
    seed: [u8; 32],
}

impl TatuKey {
    pub fn generate(mut rng: impl rand::CryptoRng + rand::RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self { seed }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn ed_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    pub fn ed_pub(&self) -> VerifyingKey {
        self.ed_key().verifying_key()
    }

    pub fn x_key(&self) -> StaticSecret {
        let hash = Sha512::digest(&self.seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        StaticSecret::from(scalar)
    }

    pub fn x_pub(&self) -> PublicKey {
        PublicKey::from(&self.x_key())
    }

    pub fn load(path: &Path) -> Result<Self, KeyError> {
        check_permissions(path)?;
        let bytes = fs::read(path)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| KeyError::InvalidLength(v.len()))?;
        Ok(Self { seed })
    }

    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        fs::write(path, &self.seed)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    pub fn load_or_generate(path: &Path) -> Result<Self, KeyError> {
        if path.exists() {
            Self::load(path)
        } else {
            let key = Self::generate(rand::rngs::OsRng);
            key.save(path)?;
            Ok(key)
        }
    }
}

impl std::fmt::Display for TatuKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.x_pub().as_bytes().to_base58())
    }
}

// TODO: Mnemonic backup/recovery (BIP39-style)
// This would allow users to backup/restore their master key using a 24-word phrase
// pub fn backup_key(secret: &x25519::StaticSecret) -> [String; 24] { todo!() }
// pub fn restore_key(words: &[String; 24]) -> Result<x25519::StaticSecret, MnemonicError> { todo!() }

// NOTE: How do I print these to server operator on first launch without getting them logged?
// The client side should probably interactively ask to input 2 random nths to verify you wrote down the phrase

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RemoteTatuKey(PublicKey);

impl RemoteTatuKey {
    pub fn from_x_pub(key: PublicKey) -> Self {
        Self(key)
    }

    pub fn from_base58(s: &str) -> Result<Self, KeyError> {
        base58_pubkey(s).map(Self)
    }

    pub fn as_x_pub(&self) -> &PublicKey {
        &self.0
    }
}

impl std::fmt::Display for RemoteTatuKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_bytes().to_base58())
    }
}

impl PartialEq<TatuKey> for RemoteTatuKey {
    fn eq(&self, other: &TatuKey) -> bool {
        self.0.as_bytes() == other.x_pub().as_bytes()
    }
}

impl PartialEq<RemoteTatuKey> for TatuKey {
    fn eq(&self, other: &RemoteTatuKey) -> bool {
        self.x_pub().as_bytes() == other.0.as_bytes()
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error(
        "Key file has world-accessible permissions (mode: {0:o}). `chmod 600 your.key` to fix."
    )]
    WorldAccessible(u32),
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("Invalid base58 encoding: {0}")]
    InvalidBase58(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

impl From<KeyError> for io::Error {
    fn from(e: KeyError) -> Self {
        match e {
            KeyError::Io(io_err) => io_err,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

pub fn base58_pubkey(s: &str) -> Result<x25519::PublicKey, KeyError> {
    let bytes = s
        .from_base58()
        .map_err(|e| KeyError::InvalidBase58(format!("{:?}", e)))?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidLength(bytes.len()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(x25519::PublicKey::from(key_bytes))
}

fn check_permissions(path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)?;
        let mode = metadata.permissions().mode();

        if mode & 0o004 != 0 {
            return Err(KeyError::WorldAccessible(mode));
        }
    }

    Ok(())
}
