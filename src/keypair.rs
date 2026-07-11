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
        #[cfg(feature = "kem-nistp")]
        Kem::DhP256HkdfSha256 => gen_kp::<hpke::kem::DhP256HkdfSha256>(),

        #[cfg(feature = "kem-nistp")]
        Kem::DhP384HkdfSha384 => gen_kp::<hpke::kem::DhP384HkdfSha384>(),

        #[cfg(feature = "kem-nistp")]
        Kem::DhP521HkdfSha512 => gen_kp::<hpke::kem::DhP521HkdfSha512>(),

        #[cfg(feature = "kem-x25519")]
        Kem::X25519HkdfSha256 => gen_kp::<hpke::kem::X25519HkdfSha256>(),

        #[cfg(feature = "kem-mlkem")]
        Kem::MlKem768 => gen_kp::<hpke::kem::MlKem768>(),

        #[cfg(feature = "kem-mlkem")]
        Kem::MlKem1024 => gen_kp::<hpke::kem::MlKem1024>(),

        #[cfg(all(feature = "kem-mlkem", feature = "kem-x25519"))]
        Kem::XWing => gen_kp::<hpke::kem::XWing>(),

        #[cfg(all(feature = "kem-mlkem", feature = "kem-nistp"))]
        Kem::MlKem768P256 => gen_kp::<hpke::kem::MlKem768P256>(),

        #[cfg(all(feature = "kem-mlkem", feature = "kem-nistp"))]
        Kem::MlKem1024P384 => gen_kp::<hpke::kem::MlKem1024P384>(),
    }
}

fn gen_kp<KemT: hpke::kem::Kem>() -> Keypair {
    let (private_key, public_key) = KemT::gen_keypair();
    let public_key = public_key.to_bytes().to_vec();
    let private_key = private_key.to_bytes().to_vec();

    Keypair {
        public_key,
        private_key,
    }
}
