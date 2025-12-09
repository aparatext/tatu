use crate::vdf::VdfProof;
use blake2::{
    Blake2b, Digest,
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
        Uuid::from_bytes(Blake2b::<U16>::digest(self.key.to_bytes()).into())
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
        let disc_bytes = Blake2b::<U4>::digest(&seed);
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
    pub vdf_proof: VdfProof,
}

// NOTE: Maybe consider replacing XEdDSA with Ed25519 -> X25519

// Its randomness makes backing up handles impossible
// and faking it will break its DH security.

// It also presents undue burden on the alternative impls,
// requiring primitives like eligator to even implement.

// The reverse however is possible. We can define our TatuKey (TatuID?) type
// to have .as_ed25519 and pass/get that in mine/verify, also consolidating
// some logic like display, while Noise gets the .as_x25519?

// We would preferably include the ed25519 key in the message, or we'd have
// to check two possible candidates.

impl HandleClaim {
    pub fn mine(nick: String, key: &x25519::StaticSecret) -> Self {
        use xeddsa::Sign;
        use xeddsa::xed25519::PrivateKey;

        let xed_key = PrivateKey::from(key);
        let nick_sig: ed25519::Signature = xed_key.sign(nick.as_bytes(), rand::rngs::OsRng);

        // TODO: Validate usernames to not include #, error otherwise.

        HandleClaim {
            nick,
            nick_sig,
            vdf_proof: VdfProof::mine(&nick_sig.to_bytes()),
        }
    }

    pub fn verify(self, key: &x25519::PublicKey) -> anyhow::Result<Handle> {
        use xeddsa::Verify;
        use xeddsa::xed25519::PublicKey;

        let xed_key = PublicKey::from(key);

        xed_key.verify(self.nick.as_bytes(), &self.nick_sig)?;
        self.vdf_proof.verify(&self.nick_sig.to_bytes())?;

        let seed = [
            &self.nick_sig.to_bytes()[..],
            &self.vdf_proof.pi.to_digits(rug::integer::Order::MsfBe)[..],
            &self.vdf_proof.y.to_digits(rug::integer::Order::MsfBe)[..],
        ]
        .concat();
        Ok(Handle::from(self.nick, seed))
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthMessage {
    pub handle_claim: HandleClaim,
    pub skin: Option<String>,
}
