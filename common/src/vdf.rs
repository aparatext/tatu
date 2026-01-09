use blake2::{Blake2s256, Digest};
use once_cell::sync::Lazy;
use rug::Integer;
use rug::integer::Order::MsfBe;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// RSA-2048 modulus from the RSA Factoring Challenge.
static N: Lazy<Integer> = Lazy::new(|| {
    let n: Integer = Integer::parse(
        "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357",
    ).expect("valid RSA-2048").into();
    assert!(n.is_odd());
    n
});
static N_HALF: Lazy<Integer> = Lazy::new(|| N.clone() / 2);

// Difficulty
const T: u32 = 1 << (if !cfg!(debug_assertions) { 24 } else { 21 });
static TWO_TO_T: Lazy<Integer> = Lazy::new(|| Integer::from(Integer::u_pow_u(2, T)));

// Wesolowski, "Efficient Verifiable Delay Functions"
//
// See https://reading.supply/@whyrusleeping/a-vdf-explainer-5S6Ect
// and https://eprint.iacr.org/2018/623.pdf

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub pi: Integer,
    pub y: Integer,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid proof")]
    InvalidProof,
}

impl Proof {
    pub fn mine(seed: &[u8]) -> Self {
        let g = hash_group(seed);
        let y = quotient_group(pow_mod(&g, &TWO_TO_T, &N));

        let l = hash_prime(&g, &y);
        let (q, _r) = TWO_TO_T.clone().div_rem(l);
        let pi = quotient_group(pow_mod(&g, &q, &N));

        Proof { pi, y }
    }

    pub fn verify(&self, seed: &[u8]) -> Result<(), Error> {
        let g = hash_group(seed);
        let l = hash_prime(&g, &self.y);
        let r = TWO_TO_T.clone() % &l;

        let rhs = quotient_group(pow_mod(&self.pi, &l, &N) * pow_mod(&g, &r, &N) % &*N);
        if self.y == rhs {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }
}

fn pow_mod(base: &Integer, exp: &Integer, n: &Integer) -> Integer {
    base.clone()
        .pow_mod(exp, n)
        .expect("N is odd, exp is non-negative")
}

// Reduce to [1, N/2] so that x and -x are treated as equal
fn quotient_group(x: Integer) -> Integer {
    if x > *N_HALF { &*N - x } else { x }
}

fn hash_group(seed: &[u8]) -> Integer {
    let digest = Blake2s256::digest(seed);
    let h = Integer::from_digits(&digest, MsfBe);
    let x = h % (N.clone() - 1) + 1;
    quotient_group(x)
}

// Fiat-Shamir challenge, must be prime to resist root-finding attacks
fn hash_prime(g: &Integer, y: &Integer) -> Integer {
    let mut hasher = Blake2s256::new();
    hasher.update(g.to_digits::<u8>(MsfBe));
    hasher.update(y.to_digits::<u8>(MsfBe));
    let h = Integer::from_digits(&hasher.finalize(), MsfBe);
    h.next_prime()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn roundtrip() {
        assert!(Proof::mine(b"x").verify(b"x").is_ok());
    }
    #[test]
    fn deterministic() {
        assert_eq!(Proof::mine(b"x").y, Proof::mine(b"x").y);
    }
    #[test]
    fn seed_sensitive() {
        assert_ne!(Proof::mine(b"a").y, Proof::mine(b"b").y);
    }

    #[test]
    fn tamper_pi() {
        let mut p = Proof::mine(b"x");
        p.pi ^= 1;
        assert!(p.verify(b"x").is_err());
    }
    #[test]
    fn tamper_y() {
        let mut p = Proof::mine(b"x");
        p.y ^= 1;
        assert!(p.verify(b"x").is_err());
    }

    #[test]
    fn negation_not_forgery() {
        let p = Proof::mine(b"x");
        let forged = Proof {
            pi: p.pi.clone(),
            y: N.clone() - &p.y,
        };
        assert!(forged.verify(b"x").is_err() || forged.y == p.y);
    }

    #[test]
    fn work_asymmetry() {
        let t0 = Instant::now();
        let p = Proof::mine(b"x");
        let mine = t0.elapsed();

        let t0 = Instant::now();
        for _ in 0..100 {
            let _ = p.verify(b"x");
        }
        let verify = t0.elapsed() / 100;

        assert!(mine > verify * 1000);
    }
}
