use crate::IdLookupError;
use num_enum::TryFromPrimitive;
use std::str::FromStr;

/// A key derivation function used in HPKE.
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
pub enum Kdf {
    /// Sha256 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    #[cfg(feature = "hkdfsha2")]
    Sha256 = 0x0001,
    /// Sha384 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    #[cfg(feature = "hkdfsha2")]
    Sha384 = 0x0002,
    /// Sha512 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    #[cfg(feature = "hkdfsha2")]
    Sha512 = 0x0003,
    /// SHAKE128 [RFC 9861](https://www.rfc-editor.org/info/rfc9861/)
    #[cfg(feature = "shake")]
    Shake128 = 0x0010,
    /// SHAKE256 [RFC 9861](https://www.rfc-editor.org/info/rfc9861/)
    #[cfg(feature = "shake")]
    Shake256 = 0x0011,
    /// TurboSHAKE128 [RFC 9861](https://www.rfc-editor.org/info/rfc9861/)
    #[cfg(feature = "shake")]
    TurboShake128 = 0x0012,
    /// TurboSHAKE256 [RFC 9861](https://www.rfc-editor.org/info/rfc9861/)
    #[cfg(feature = "shake")]
    TurboShake256 = 0x0013,
}

impl FromStr for Kdf {
    type Err = IdLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s.to_lowercase().replace('-', "") {
            #[cfg(feature = "hkdfsha2")]
            "hkdfsha256" | "sha256" => Ok(Self::Sha256),
            #[cfg(feature = "hkdfsha2")]
            "hkdfsha384" | "sha384" => Ok(Self::Sha384),
            #[cfg(feature = "hkdfsha2")]
            "hkdfsha512" | "sha512" => Ok(Self::Sha512),
            #[cfg(feature = "shake")]
            "shake128" => Ok(Self::Shake128),
            #[cfg(feature = "shake")]
            "shake256" => Ok(Self::Shake256),
            #[cfg(feature = "shake")]
            "turboshake128" => Ok(Self::TurboShake128),
            #[cfg(feature = "shake")]
            "turboshake256" => Ok(Self::TurboShake256),
            _ => Err(IdLookupError("kdf not recognized")),
        }
    }
}

/// An iterable slice of [`Kdf`] variants
pub const KDF_ALL: &[Kdf] = &[
    #[cfg(feature = "hkdfsha2")]
    Kdf::Sha256,
    #[cfg(feature = "hkdfsha2")]
    Kdf::Sha384,
    #[cfg(feature = "hkdfsha2")]
    Kdf::Sha512,
    #[cfg(feature = "shake")]
    Kdf::Shake128,
    #[cfg(feature = "shake")]
    Kdf::Shake256,
    #[cfg(feature = "shake")]
    Kdf::TurboShake128,
    #[cfg(feature = "shake")]
    Kdf::TurboShake256,
];
