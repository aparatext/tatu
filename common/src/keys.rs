use serde::{Deserialize, Serialize};
use std::fmt;
use std::{fs, io, path::Path};
use thiserror::Error;

use blake2::{Blake2s256, Digest};
use ed25519::{SigningKey, VerifyingKey};
use x25519::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use base58::{FromBase58, ToBase58};
use proquint::Quintable;

const RECOVERY_WORDS: usize = 12;
const ECC_BYTES: usize = (RECOVERY_WORDS * 2) - 16;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase([u8; 16]);

impl RecoveryPhrase {
    pub fn from_entropy(entropy: [u8; 16]) -> Self {
        Self(entropy)
    }

    pub fn to_entropy(&self) -> [u8; 16] {
        self.0
    }

    pub fn parse(s: &str) -> Result<(Self, usize), RecoveryError> {
        let words: Vec<&str> = s.split(['-', ' ']).collect();

        if words.len() != RECOVERY_WORDS {
            return Err(RecoveryError::InvalidFormat);
        }

        let mut encoded_bytes = Vec::with_capacity(RECOVERY_WORDS * 2);
        for (i, pq) in words.iter().enumerate() {
            let value = match u16::from_quint(pq) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(
                        "Invalid proquint at position {}: '{}', treating as 0x0000",
                        i,
                        pq
                    );
                    0
                }
            };
            let bytes = value.to_be_bytes();
            encoded_bytes.push(bytes[0]);
            encoded_bytes.push(bytes[1]);
        }

        let dec = reed_solomon::Decoder::new(ECC_BYTES);
        let (corrected, num_errors) = dec
            .correct_err_count(&encoded_bytes, None)
            .map_err(|_| RecoveryError::TooManyErrors)?;

        if num_errors > 0 {
            tracing::info!("Corrected {} bytes in recovery phrase", num_errors);
        }

        let data = corrected.data();
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&data[..16]);

        Ok((Self(entropy), num_errors))
    }
}

impl fmt::Display for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use reed_solomon::Encoder;
        use std::ops::Deref;

        let enc = Encoder::new(ECC_BYTES);
        let encoded = enc.encode(&self.0);

        let all_bytes: &[u8] = encoded.deref();
        let mut words: Vec<String> = Vec::with_capacity(RECOVERY_WORDS);

        for chunk in all_bytes.chunks_exact(2) {
            let value = u16::from_be_bytes([chunk[0], chunk[1]]);
            words.push(value.to_quint());
        }

        let mut joined = words.join("-");
        let result = write!(f, "{}", joined);

        joined.zeroize();
        for w in &mut words {
            w.zeroize();
        }

        result
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TatuKey {
    #[serde(with = "serde_bytes")]
    seed: [u8; 32],
}

impl TatuKey {
    pub fn ed_pub(&self) -> VerifyingKey {
        self.ed_key().verifying_key()
    }

    pub fn ed_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    pub fn x_pub(&self) -> PublicKey {
        PublicKey::from(&self.x_key())
    }

    pub fn x_key(&self) -> StaticSecret {
        StaticSecret::from(self.ed_key().to_scalar_bytes())
    }

    pub fn load_or_generate(
        path: &Path,
        phrase: Option<&RecoveryPhrase>,
    ) -> Result<(Self, Option<RecoveryPhrase>), KeyError> {
        if path.exists() {
            let key = Self::load(path)?;
            Ok((key, None))
        } else if let Some(phrase_vec) = phrase {
            let key = Self::recover(phrase_vec);
            key.save(path)?;
            Ok((key, None))
        } else {
            let (key, phrase_vec) = Self::generate(rand::rngs::OsRng);
            key.save(path)?;
            Ok((key, Some(phrase_vec)))
        }
    }

    pub fn generate(mut rng: impl rand::CryptoRng + rand::RngCore) -> (Self, RecoveryPhrase) {
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);

        let expanded = Blake2s256::digest(entropy).into();
        let phrase = RecoveryPhrase::from_entropy(entropy);

        entropy.zeroize();
        (Self { seed: expanded }, phrase)
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
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.seed)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    pub fn recover(phrase: &RecoveryPhrase) -> Self {
        let expanded = Blake2s256::digest(phrase.to_entropy());
        Self {
            seed: expanded.into(),
        }
    }
}

impl std::fmt::Display for TatuKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.x_pub().as_bytes().to_base58())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RemoteTatuKey(PublicKey);

impl RemoteTatuKey {
    pub fn from_x_pub(key: PublicKey) -> Self {
        Self(key)
    }

    pub fn from_ed_pub(ed_pub: &VerifyingKey) -> Self {
        Self(PublicKey::from(ed_pub.to_montgomery().to_bytes()))
    }

    pub fn x_pub(&self) -> &PublicKey {
        &self.0
    }

    pub fn from_base58(s: &str) -> Result<Self, KeyError> {
        let bytes = s
            .from_base58()
            .map_err(|e| KeyError::InvalidBase58(format!("{:?}", e)))?;

        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength(bytes.len()));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        Ok(Self(x25519::PublicKey::from(key_bytes)))
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
    #[error("Key file has world-accessible permissions (mode: {0:o}). To fix: chmod 600 your.key")]
    WorldAccessible(u32),
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("Invalid base58 encoding: {0}")]
    InvalidBase58(String),
    #[error("Recovery phrase error: {0}")]
    Recovery(#[from] RecoveryError),
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

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("Invalid recovery phrase format (expected {RECOVERY_WORDS} proquints)")]
    InvalidFormat,
    #[error("Invalid proquint: {0}")]
    InvalidProquint(String),
    #[error("Too many errors to correct (can correct up to {} proquints = {} characters)", ECC_BYTES / 4, ECC_BYTES / 4 * 5)]
    TooManyErrors,
    #[error("Reed-Solomon decoding failed: {0}")]
    RsError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519::{Signer, Verifier};
    use rand::Rng;

    #[test]
    fn xed_binding() {
        let (key, _) = TatuKey::generate(rand::rngs::OsRng);

        let ed_pub = key.ed_pub();
        let x_pub = key.x_pub();
        let sig = key.ed_key().sign(b"test message");

        let derived_id = RemoteTatuKey::from_ed_pub(&ed_pub);
        assert_eq!(derived_id.x_pub().as_bytes(), x_pub.as_bytes());

        assert!(ed_pub.verify(b"test message", &sig).is_ok());
    }

    #[test]
    fn recovery_roundtrip() {
        let (key1, phrase) = TatuKey::generate(rand::rngs::OsRng);
        let phrase_str = phrase.to_string();
        println!("Recovery phrase: {}", phrase_str);

        let (parsed, corrections) = RecoveryPhrase::parse(&phrase_str).unwrap();
        assert_eq!(corrections, 0);

        let key2 = TatuKey::recover(&parsed);

        assert_eq!(key1.ed_pub().as_bytes(), key2.ed_pub().as_bytes());
        assert_eq!(key1.x_pub().as_bytes(), key2.x_pub().as_bytes());
    }

    #[test]
    fn recovery_ecc() {
        let mut rng = rand::rngs::OsRng;
        let (_, phrase) = TatuKey::generate(rand::rngs::OsRng);

        let mut words: Vec<String> = phrase.to_string().split('-').map(String::from).collect();

        let max_proquints = ECC_BYTES / 4;
        let data_words = RECOVERY_WORDS - (ECC_BYTES / 2);

        let mut corrupted = std::collections::HashSet::new();
        while corrupted.len() < max_proquints {
            let i = rng.gen_range(0..data_words);
            if corrupted.insert(i) {
                let random_value = rng.gen_range(0..=u16::MAX);
                words[i] = random_value.to_quint();
            }
        }

        let corrupted_str = words.join("-");
        let (recovered, corrections) = RecoveryPhrase::parse(&corrupted_str).unwrap();
        assert!(corrections > 0);

        let key_original = TatuKey::recover(&phrase);
        let key_recovered = TatuKey::recover(&recovered);
        assert_eq!(
            key_original.ed_pub().as_bytes(),
            key_recovered.ed_pub().as_bytes()
        );
    }

    #[test]
    fn recovery_too_many_errors() {
        let (_, phrase) = TatuKey::generate(rand::rngs::OsRng);

        let mut words: Vec<String> = phrase.to_string().split('-').map(String::from).collect();

        let too_many = (ECC_BYTES / 4) + 1;
        for i in 0..too_many {
            words[i] = "babab".to_string();
        }

        let corrupted_str = words.join("-");
        assert!(RecoveryPhrase::parse(&corrupted_str).is_err());
    }
}
