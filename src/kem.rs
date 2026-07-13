use crate::{IdLookupError, Keypair};
use num_enum::TryFromPrimitive;
use std::str::FromStr;

/// An asymmetric key encapsulation mechanism.
///
/// Codepoints are defined in [RFC9180§7.2][1] and [draft-ietf-hpke-pq][2].
///
/// [1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2
/// [2]: https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#table-1
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
    #[cfg(feature = "nistp")]
    DhP256HkdfSha256 = 0x0010,

    /// DHKEM(P-384, HKDF-SHA384) [NISTCurves](https://doi.org/10.6028/nist.fips.186-4)
    #[cfg(feature = "nistp")]
    DhP384HkdfSha384 = 0x0011,

    /// DHKEM(P-521, HKDF-SHA512) [NISTCurves](https://doi.org/10.6028/nist.fips.186-4)
    #[cfg(feature = "nistp")]
    DhP521HkdfSha512 = 0x0012,

    /// DHKEM(X25519, HKDF-SHA256) [RFC7748](https://www.rfc-editor.org/info/rfc7748)
    #[cfg(feature = "x25519")]
    X25519HkdfSha256 = 0x0020,

    /// MLKEM-768 [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
    #[cfg(feature = "mlkem")]
    MlKem768 = 0x0041,

    /// MLKEM-1024 [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
    #[cfg(feature = "mlkem")]
    MlKem1024 = 0x0042,

    /// X-Wing (MLKEM768-X25519) <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html>
    #[cfg(all(feature = "mlkem", feature = "x25519"))]
    XWing = 0x647a,

    /// MLKEM768-P256 <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html>
    #[cfg(all(feature = "mlkem", feature = "nistp"))]
    MlKem768P256 = 0x0050,

    /// MLKEM1024-P384 <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html>
    #[cfg(all(feature = "mlkem", feature = "nistp"))]
    MlKem1024P384 = 0x0051,
}

impl FromStr for Kem {
    type Err = IdLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s.to_lowercase().replace('-', "") {
            #[cfg(feature = "nistp")]
            "p256sha256" | "dhkemp256hkdfsha256" | "p256hkdfsha256" | "dhkem(p256, hkdfsha256)" => {
                Ok(Self::DhP256HkdfSha256)
            }
            #[cfg(feature = "nistp")]
            "p384sha384" | "dhkemp384hkdfsha384" | "p384hkdfsha384" | "dhkem(p384, hkdfsha384)" => {
                Ok(Self::DhP384HkdfSha384)
            }
            #[cfg(feature = "nistp")]
            "p521sha512" | "dhkemp521hkdfsha512" | "p521hkdfsha512" | "dhkem(p521, hkdfsha512)" => {
                Ok(Self::DhP521HkdfSha512)
            }
            #[cfg(feature = "x25519")]
            "x25519sha256"
            | "dhkemx25519hkdfsha256"
            | "x25519hkdfsha256"
            | "dhkem(x25519, hkdfsha256)" => Ok(Self::X25519HkdfSha256),
            #[cfg(feature = "mlkem")]
            "mlkem768" => Ok(Self::MlKem768),
            #[cfg(feature = "mlkem")]
            "mlkem1024" => Ok(Self::MlKem1024),
            #[cfg(all(feature = "mlkem", feature = "x25519"))]
            "xwing" | "mlkem768x25119" | "mlkem768-x25119" => Ok(Self::XWing),
            #[cfg(all(feature = "mlkem", feature = "nistp"))]
            "mlkem768p256" | "mlkem768-p256" => Ok(Self::MlKem768P256),
            #[cfg(all(feature = "mlkem", feature = "nistp"))]
            "mlkem1024p384" | "mlkem1024-p384" => Ok(Self::MlKem1024P384),
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
    #[cfg(feature = "nistp")]
    Kem::DhP256HkdfSha256,
    #[cfg(feature = "nistp")]
    Kem::DhP384HkdfSha384,
    #[cfg(feature = "nistp")]
    Kem::DhP521HkdfSha512,
    #[cfg(feature = "x25519")]
    Kem::X25519HkdfSha256,
    #[cfg(feature = "mlkem")]
    Kem::MlKem768,
    #[cfg(feature = "mlkem")]
    Kem::MlKem1024,
    #[cfg(all(feature = "mlkem", feature = "x25519"))]
    Kem::XWing,
    #[cfg(all(feature = "mlkem", feature = "nistp"))]
    Kem::MlKem768P256,
    #[cfg(all(feature = "mlkem", feature = "nistp"))]
    Kem::MlKem1024P384,
];
