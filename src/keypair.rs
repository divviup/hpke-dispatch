#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::Kem;
use hpke::Serializable;

/// An encoded keypair
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone))]
pub struct Keypair {
    /// the public key for this keypair
    pub public_key: Vec<u8>,

    /// the private key for this keypair,
    pub private_key: Vec<u8>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Keypair {
    /// generate a keypair from a [`Kem`]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
    #[must_use]
    pub fn new(kem: Kem) -> Keypair {
        gen_keypair(kem)
    }
}

impl Keypair {
    /// deconstructs the pair into (private, public)
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.private_key, self.public_key)
    }
}

/// generate a Keypair for the provided asymmetric key encapsulation mechanism ([`Kem`])
#[must_use]
pub fn gen_keypair(kem: Kem) -> Keypair {
    match kem {
        #[cfg(feature = "kem-dh-p256-hkdf-sha256")]
        Kem::DhP256HkdfSha256 => gen_kp::<hpke::kem::DhP256HkdfSha256>(),

        #[cfg(feature = "kem-x25519-hkdf-sha256")]
        Kem::X25519HkdfSha256 => gen_kp::<hpke::kem::X25519HkdfSha256>(),
    }
}

fn gen_kp<KemT: hpke::kem::Kem>() -> Keypair {
    let (private_key, public_key) = KemT::gen_keypair(&mut rand::thread_rng());
    let public_key = public_key.to_bytes().to_vec();
    let private_key = private_key.to_bytes().to_vec();

    Keypair {
        public_key,
        private_key,
    }
}
