use crate::{IdLookupError, Keypair};
use num_enum::TryFromPrimitive;
use std::str::FromStr;

/**
Kem represents an asymmetric key encapsulation mechanism, as per
[RFC9180§7.1][section-7.1]. Currently only four of the options listed in
the hpke draft are available.

[section-7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
*/
#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum Kem {
    /// DHKEM(P-256, HKDF-SHA256) [NISTCurves](https://doi.org/10.6028/nist.fips.186-4)
    #[cfg(feature = "kem-nistp")]
    DhP256HkdfSha256 = 16,

    /// DHKEM(P-384, HKDF-SHA384) [NISTCurves](https://doi.org/10.6028/nist.fips.186-4)
    #[cfg(feature = "kem-nistp")]
    DhP384HkdfSha384 = 17,

    /// DHKEM(P-521, HKDF-SHA512) [NISTCurves](https://doi.org/10.6028/nist.fips.186-4)
    #[cfg(feature = "kem-nistp")]
    DhP521HkdfSha512 = 18,

    /// DHKEM(X25519, HKDF-SHA256) [RFC7748](https://www.rfc-editor.org/info/rfc7748)
    #[cfg(feature = "kem-x25519")]
    X25519HkdfSha256 = 32,
}

impl FromStr for Kem {
    type Err = IdLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s.to_lowercase().replace('-', "") {
            #[cfg(feature = "kem-nistp")]
            "p256sha256" | "dhkemp256hkdfsha256" | "p256hkdfsha256" | "dhkem(p256, hkdfsha256)" => {
                Ok(Self::DhP256HkdfSha256)
            }
            #[cfg(feature = "kem-nistp")]
            "p384sha384" | "dhkemp384hkdfsha384" | "p384hkdfsha384" | "dhkem(p384, hkdfsha384)" => {
                Ok(Self::DhP384HkdfSha384)
            }
            #[cfg(feature = "kem-nistp")]
            "p521sha512" | "dhkemp521hkdfsha512" | "p521hkdfsha512" | "dhkem(p521, hkdfsha512)" => {
                Ok(Self::DhP521HkdfSha512)
            }
            #[cfg(feature = "kem-x25519")]
            "x25519sha256"
            | "dhkemx25519hkdfsha256"
            | "x25519hkdfsha256"
            | "dhkem(x25519, hkdfsha256)" => Ok(Self::X25519HkdfSha256),
            _ => Err(IdLookupError("kem not recognized")),
        }
    }
}

impl Kem {
    /// generate a [`Keypair`] for this [`Kem`].
    #[must_use]
    pub fn gen_keypair(self) -> Keypair {
        crate::gen_keypair(self)
    }
}

/// An iterable slice of [`Kem`] variants
pub const KEM_ALL: &[Kem] = &[
    #[cfg(feature = "kem-nistp")]
    Kem::DhP256HkdfSha256,
    #[cfg(feature = "kem-nistp")]
    Kem::DhP384HkdfSha384,
    #[cfg(feature = "kem-nistp")]
    Kem::DhP521HkdfSha512,
    #[cfg(feature = "kem-x25519")]
    Kem::X25519HkdfSha256,
];
