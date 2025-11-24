use crate::Kem;
use hpke::Serializable;

/// An encoded keypair
#[derive(Debug, Clone, Eq, PartialEq, zeroize::Zeroize)]
pub struct Keypair {
    /// the public key for this keypair
    pub public_key: Vec<u8>,

    /// the private key for this keypair,
    pub private_key: Vec<u8>,
}

impl Keypair {
    /// generate a keypair from a [`Kem`]
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

        #[cfg(feature = "kem-dh-p384-hkdf-sha384")]
        Kem::DhP384HkdfSha384 => gen_kp::<hpke::kem::DhP384HkdfSha384>(),

        #[cfg(feature = "kem-dh-p521-hkdf-sha512")]
        Kem::DhP521HkdfSha512 => gen_kp::<hpke::kem::DhP521HkdfSha512>(),

        #[cfg(feature = "kem-x25519-hkdf-sha256")]
        Kem::X25519HkdfSha256 => gen_kp::<hpke::kem::X25519HkdfSha256>(),
    }
}

fn gen_kp<KemT: hpke::kem::Kem>() -> Keypair {
    let (private_key, public_key) = KemT::gen_keypair(&mut rand::rng());
    let public_key = public_key.to_bytes().to_vec();
    let private_key = private_key.to_bytes().to_vec();

    Keypair {
        public_key,
        private_key,
    }
}
