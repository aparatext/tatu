use crate::keys::RemoteTatuKey;
use crate::vdf;
use anyhow::anyhow;
use blake2::{
    Blake2s, Digest,
    digest::consts::{U4, U16},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct Persona {
    pub key: x25519::PublicKey,
    pub handle: Handle,
    pub skin: Option<String>,
}

impl Persona {
    pub fn uuid(&self) -> Uuid {
        Uuid::from_bytes(Blake2s::<U16>::digest(self.key.to_bytes()).into())
    }

    pub fn auth(
        key: x25519::PublicKey,
        claim: HandleClaim,
        skin: Option<String>,
    ) -> anyhow::Result<Self> {
        let handle = claim.verify(&key)?;
        Ok(Persona { key, handle, skin })
    }
}

impl std::fmt::Display for Persona {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} ({})", self.handle, self.uuid().as_hyphenated())
    }
}

pub struct Handle {
    pub nick: String,
    pub discriminator: String,
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}#{}", self.nick, self.discriminator)
    }
}

impl Handle {
    pub fn from(nick: String, seed: Vec<u8>) -> Self {
        let disc_bytes = Blake2s::<U4>::digest(&seed);
        let disc_u32 = u32::from_be_bytes(disc_bytes.into());

        let discriminator = Self::discriminator(disc_u32);
        Handle {
            nick,
            discriminator,
        }
    }

    // NOTE: COGDEBT: Base conversion
    pub fn discriminator(n: u32) -> String {
        const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

        let digits = n % 10000;
        let letters = n / 10000;

        let mut letter_str = String::with_capacity(4);
        let mut temp = letters;
        for _ in 0..4 {
            letter_str.push(LETTERS[(temp % 26) as usize] as char);
            temp /= 26;
        }

        format!(
            "{}{:04}",
            letter_str.chars().rev().collect::<String>(),
            digits
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HandleClaim {
    pub nick: String,
    pub nick_sig: ed25519::Signature,
    pub sig_key: ed25519::VerifyingKey,
    pub vdf_proof: vdf::Proof,
}

impl HandleClaim {
    pub fn mine(nick: String, sig_key: &ed25519::SigningKey) -> anyhow::Result<Self> {
        use ed25519::Signer;

        if !nick.chars().all(|c| c.is_alphanumeric()) {
            return Err(anyhow!("Nick must only contain alphanumeric characters"));
        }

        let nick_sig = sig_key.sign(nick.as_bytes());

        Ok(HandleClaim {
            nick,
            nick_sig,
            sig_key: sig_key.verifying_key(),
            vdf_proof: vdf::Proof::mine(&nick_sig.to_bytes()),
        })
    }

    pub fn verify(&self, x_pub: &x25519::PublicKey) -> anyhow::Result<Handle> {
        use ed25519::Verifier;

        if !self.nick.chars().all(|c| c.is_alphanumeric()) {
            return Err(anyhow!("Nick must only contain alphanumeric characters"));
        }

        self.sig_key.verify(self.nick.as_bytes(), &self.nick_sig)?;

        let signer = RemoteTatuKey::from_ed_pub(&self.sig_key);
        if signer.x_pub() != x_pub {
            return Err(anyhow!("sig key unbound from auth key!"));
        }

        self.vdf_proof.verify(&self.nick_sig.to_bytes())?;

        let seed = [
            &self.nick_sig.to_bytes()[..],
            &self.vdf_proof.pi.to_digits(rug::integer::Order::MsfBe)[..],
            &self.vdf_proof.y.to_digits(rug::integer::Order::MsfBe)[..],
        ]
        .concat();
        Ok(Handle::from(self.nick.clone(), seed))
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthMessage {
    pub handle_claim: HandleClaim,
    pub skin: Option<String>,
}
