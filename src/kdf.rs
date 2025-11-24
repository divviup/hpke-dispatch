use crate::IdLookupError;
use num_enum::TryFromPrimitive;
use std::str::FromStr;

/**
Kdf represents an key derivation function, as per
[RFC9180§7.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2)
*/
#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum Kdf {
    #[cfg(feature = "kdf-sha256")]
    /// Sha256 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    Sha256 = 1,
    #[cfg(feature = "kdf-sha384")]
    /// Sha384 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    Sha384 = 2,
    #[cfg(feature = "kdf-sha512")]
    /// Sha512 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    Sha512 = 3,
}

impl FromStr for Kdf {
    type Err = IdLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s.to_lowercase().replace('-', "") {
            #[cfg(feature = "kdf-sha256")]
            "hkdfsha256" | "sha256" => Ok(Self::Sha256),
            #[cfg(feature = "kdf-sha384")]
            "hkdfsha384" | "sha384" => Ok(Self::Sha384),
            #[cfg(feature = "kdf-sha512")]
            "hkdfsha512" | "sha512" => Ok(Self::Sha512),
            _ => Err(IdLookupError("kdf not recognized")),
        }
    }
}

/// An iterable slice of [`Kdf`] variants
pub const KDF_ALL: &[Kdf] = &[
    #[cfg(feature = "kdf-sha256")]
    Kdf::Sha256,
    #[cfg(feature = "kdf-sha384")]
    Kdf::Sha384,
    #[cfg(feature = "kdf-sha512")]
    Kdf::Sha512,
];
