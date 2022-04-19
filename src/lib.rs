#![cfg_attr(feature = "cfg_eval", feature(cfg_eval))]
#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    nonstandard_style,
    unused_qualifications
)]
#![warn(missing_docs, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc
)]

/*!
# Hybrid public key encryption with algorithms dispatched at runtime

This crate provides a generic-free interface to the [`hpke`][hpke]
crate, a rust implementation of the draft [hybrid public key
encryption](https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html)
scheme. If you know the specific (aead, kdf, kem) triple at compile
time, you should use the [`hpke`][hpke] crate directly.

Currently, this crate only exposes interfaces for the Base mode (0)
described in the hpke draft, and within base mode, only stateless
single-shot message encryption/decryption, as defined in [section
6](https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html#section-6)

## Nightly-only feature to work around a wasm-bindgen bug: `cfg_eval`

In order to opt out of `algo-all` for a wasm build, you must use
nightly and enable the `cfg_eval` cargo feature. This is due to
[wasm-bindgen#2058][wasm-bindgen-2058]. This is not necessary for use
from rust, even when opting out of `algo-all`.

[hpke]: https://docs.rs/hpke/latest/hpke/
[wasm-bindgen-2058]: https://github.com/rustwasm/wasm-bindgen/issues/2058

## Available cargo features:

* *`cfg_eval`*: allows this crate to be built on nightly rust for wasm
  without `algo-all`. Note that `algo-all` (all
  algorithms) will build for wasm on any channel without this feature.
  disabled by default. Attempting to build for wasm with a subset.

* *base-mode-open*: Enables hpke base-mode one-shot open behavior
  (receiver functionality). See [`base_mode_open`]
  and [`Config::base_mode_open`]. Enabled by default.

* *base-mode-seal*: Enables hpke base-mode one-shot seal behavior
  (sender functionality). See [`base_mode_seal`]
  and [`Config::base_mode_seal`]. Enabled by default.

* *algo-all*: enables all aead, kdf, and kem algorithms. enabled by
  default.

* *aead-all*: Enables `aead-aes-gcm-128`, `aead-aes-gcm-256`, and
  `aead-chacha-20-poly-1305` algorithm features. Enabled by default.

* *kdf-all*: Enables `kdf-sha256`, `kdf-sha384`, `kdf-sha512`
  algorithm features. Enabled by default.

* *kem-all*: Enables both `kem-dh-p256-hkdf-sha256` and
 `kem-x25519-hkdf-sha256` algorithm features. Enabled by default.

* *serde*: enables derived serde serialization and deserialization for
  all public structs and enums. Disabled by default.

## Example feature usage:

To depend on this crate from rust with all algorithms,
`base-mode-open`, and `base-mode-seal`, use default features.

To depend on this crate from rust with all algorithms and serde
enabled, but without `base-mode-seal`: `default-features = false,
features = ["algo-all", "base-mode-open", "serde"]`

To build for wasm without `kem-x25519-hkdf-sha256` or
`base-mode-open`: `wasm-pack build --no-default-features --features
aead-all,kdf-all,kem-dh-p256-hkdf-sha256,base-mode-seal,cfg_eval`

To build for wasm with all algorithms but without base-mode-open:
`wasm-pack build --no-default-features --features
algo-all,base-mode-seal`


*/

use hpke::Deserializable;
use num_enum::TryFromPrimitive;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/**
Aead represents an authenticated encryption with additional data
encryption function, as per [§7.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html#section-7.3)
*/
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
#[cfg_attr(feature = "cfg_eval", cfg_eval)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub enum Aead {
    #[cfg(feature = "aead-aes-gcm-128")]
    /// AES-128-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    AesGcm128 = 1,
    #[cfg(feature = "aead-aes-gcm-256")]
    /// AES-256-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    AesGcm256 = 2,
    #[cfg(feature = "aead-chacha-20-poly-1305")]
    /// ChaCha20Poly1305 [RFC8439](https://www.rfc-editor.org/info/rfc8439)
    ChaCha20Poly1305 = 3,
}

/**
Kdf represents an key derivation function, as per
[§7.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html#section-7.2)
*/
#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
#[cfg_attr(feature = "cfg_eval", cfg_eval)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
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

/**
Kem represents an asymmetric key encapsulation mechanism, as per
[§7.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html#section-7.1). Currently
only two of options listed in the hpke draft are available.
*/
#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
#[cfg_attr(feature = "cfg_eval", cfg_eval)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub enum Kem {
    /// DHKEM(P-256, HKDF-SHA256) [NISTCurves](https://doi.org/10.6028/nist.fips.186-4)
    #[cfg(feature = "kem-dh-p256-hkdf-sha256")]
    DhP256HkdfSha256 = 10,

    /// DHKEM(X25519, HKDF-SHA256) [RFC7748](https://www.rfc-editor.org/info/rfc7748)
    #[cfg(feature = "kem-x25519-hkdf-sha256")]
    X25519HkdfSha256 = 20,
}

/**
Config is an open struct that contains an ([`Aead`], [`Kdf`], [`Kem`])
algorithmic triple. This can be used with [`Config::base_mode_seal`],
[`Config::base_mode_open`], [`base_mode_seal`], or [`base_mode_open`].
*/
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Config {
    /// the [authenticated encryption with additional data encryption function](crate::Aead) to be used
    pub aead: Aead,
    /// the [key derivation function](crate::Kdf) to be used
    pub kdf: Kdf,
    /// the [asymmetric key encapsulation mechanism](crate::Kem) to be used
    pub kem: Kem,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Config {
    /**
    base_mode_seal provides an interface to [`hpke::single_shot_seal`] that does
    not require compile time selection of an algorithm. Instead, the
    selected algorithm is provided through the [`Config`] that this
    method is called on.

    Requires the `base-mode-seal` crate feature to be enabled.

    # Errors

    This will return an `Result::Err` variant if:

     * we are unable to deserialize the recipient public key
     * there is an error in key encapsultion
     * there is an error in encryption

     */
    #[cfg(feature = "base-mode-seal")]
    pub fn base_mode_seal(
        self,
        pk_recip: &[u8],
        info: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncappedKeyAndCiphertext, HpkeError> {
        base_mode_seal(self, pk_recip, info, plaintext, aad)
    }

    /**
    base_mode_open provides an interface to [`hpke::single_shot_open`]
    that does not require compile time selection of an
    algorithm. Instead, the selected algorithm is provided through the
    [`Config`] that this method is called on.

    Requires the `base-mode-open` crate feature to be enabled.

    # Errors

    This will return an `Result::Err` variant if:

    * we are unable to deserialize the private key or encapsulated key
    * there is an error in key decapsulation
    * there is an error in decryption

    */
    #[cfg(feature = "base-mode-open")]
    pub fn base_mode_open(
        self,
        private_key: &[u8],
        ciphertext: &[u8],
        encapped_key: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        base_mode_open(self, private_key, ciphertext, encapped_key, info, aad)
    }
}

/**
*/
#[derive(Copy, Clone, Debug)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct IdLookupError;
impl std::fmt::Display for IdLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("id lookup error")
    }
}
impl std::error::Error for IdLookupError {}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Config {
    /// Attempt to convert three u16 ids into a valid config. The id mappings are defined in the draft.
    pub fn try_from_ids(aead_id: u16, kdf_id: u16, kem_id: u16) -> Result<Self, IdLookupError> {
        Ok(Self {
            aead: aead_id.try_into().map_err(|_| IdLookupError)?,
            kdf: kdf_id.try_into().map_err(|_| IdLookupError)?,
            kem: kem_id.try_into().map_err(|_| IdLookupError)?,
        })
    }
}

fn from_bytes<T: Deserializable>(encoded: &[u8]) -> Result<T, HpkeError> {
    T::from_bytes(encoded)
}

#[cfg(feature = "base-mode-seal")]
fn seal<AeadT, KdfT, KemT>(
    pk_recip: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncappedKeyAndCiphertext, HpkeError>
where
    AeadT: hpke::aead::Aead,
    KdfT: hpke::kdf::Kdf,
    KemT: hpke::kem::Kem,
{
    use hpke::Serializable;

    let (encapped_key, ciphertext) = hpke::single_shot_seal::<AeadT, KdfT, KemT, _>(
        &hpke::OpModeS::Base,
        &from_bytes(pk_recip)?,
        info,
        plaintext,
        aad,
        &mut rand::thread_rng(),
    )?;

    Ok(EncappedKeyAndCiphertext {
        encapped_key: encapped_key.to_bytes().to_vec(),
        ciphertext,
    })
}

#[cfg(feature = "base-mode-open")]
fn open<AeadT, KdfT, KemT>(
    private_key: &[u8],
    ciphertext: &[u8],
    encapped_key: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError>
where
    AeadT: hpke::aead::Aead,
    KdfT: hpke::kdf::Kdf,
    KemT: hpke::kem::Kem,
{
    hpke::single_shot_open::<AeadT, KdfT, KemT>(
        &hpke::OpModeR::Base,
        &from_bytes(private_key)?,
        &from_bytes(encapped_key)?,
        info,
        ciphertext,
        aad,
    )
}

macro_rules! match_kem {
    ($aead:ty, $kdf:ty, $kem:expr, $fn:ident) => {
        match $kem {
            #[cfg(feature = "kem-dh-p256-hkdf-sha256")]
            Kem::DhP256HkdfSha256 => $fn::<$aead, $kdf, hpke::kem::DhP256HkdfSha256>,
            #[cfg(feature = "kem-x25519-hkdf-sha256")]
            Kem::X25519HkdfSha256 => $fn::<$aead, $kdf, hpke::kem::X25519HkdfSha256>,
        }
    };
}

macro_rules! match_kdf {
    ($aead:ty, $kdf:expr, $kem:expr, $fn:ident) => {
        match $kdf {
            #[cfg(feature = "kdf-sha256")]
            Kdf::Sha256 => match_kem!($aead, hpke::kdf::HkdfSha256, $kem, $fn),
            #[cfg(feature = "kdf-sha384")]
            Kdf::Sha384 => match_kem!($aead, hpke::kdf::HkdfSha384, $kem, $fn),
            #[cfg(feature = "kdf-sha512")]
            Kdf::Sha512 => match_kem!($aead, hpke::kdf::HkdfSha512, $kem, $fn),
        }
    };
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        #[wasm_bindgen]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct EncappedKeyAndCiphertext {
            /// the encapsulated encryption key
            encapped_key: Vec<u8>,
            /// the ciphertext, encrypted with the encapsulated key
            ciphertext: Vec<u8>
        }

        #[wasm_bindgen]
        pub struct HpkeError(hpke::HpkeError);
        impl From<hpke::HpkeError> for HpkeError {
            fn from(h: hpke::HpkeError) -> Self {
                Self(h)
            }
        }

        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    } else {
        /**
        a simple open struct to return the combined encapsulated key
        and ciphertext from seal
        */
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct EncappedKeyAndCiphertext {
            /// the encapsulated encryption key
            pub encapped_key: Vec<u8>,
            /// the ciphertext, encrypted with the encapsulated key
            pub ciphertext: Vec<u8>
        }

        pub use hpke::HpkeError;
    }
}

#[cfg(target_arch = "wasm32")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl EncappedKeyAndCiphertext {
    #[wasm_bindgen(getter)]
    pub fn encapped_key(&self) -> Vec<u8> {
        self.encapped_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

/**
`base_mode_seal` provides an interface to [`hpke::single_shot_seal`]
that does not require compile time selection of an
algorithm. Instead, the selected algorithm is provided through the
[`Config`] passed as the first argument.

Requires the `base-mode-seal` crate feature to be enabled.

# Errors

This will return an `Result::Err` variant if:

* we are unable to deserialize the recipient public key
* there is an error in key encapsultion
* there is an error in encryption

 */
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg(feature = "base-mode-seal")]
pub fn base_mode_seal(
    config: Config,
    pk_recip: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncappedKeyAndCiphertext, HpkeError> {
    let Config { aead, kdf, kem } = config;

    let seal = match aead {
        #[cfg(feature = "aead-aes-gcm-128")]
        Aead::AesGcm128 => match_kdf!(hpke::aead::AesGcm128, kdf, kem, seal),
        #[cfg(feature = "aead-aes-gcm-256")]
        Aead::AesGcm256 => match_kdf!(hpke::aead::AesGcm256, kdf, kem, seal),
        #[cfg(feature = "aead-chacha-20-poly-1305")]
        Aead::ChaCha20Poly1305 => match_kdf!(hpke::aead::ChaCha20Poly1305, kdf, kem, seal),
    };

    seal(pk_recip, info, plaintext, aad)
}

/**
`base_mode_open` provides an interface to [`hpke::single_shot_open`]
that does not require compile time selection of an algorithm. Instead,
the selected algorithm is provided through the [`Config`] passed as
the first argument.

Requires the `base-mode-open` crate feature to be enabled.

# Errors

This will return an `Result::Err` variant if:

* we are unable to deserialize the private key or encapsulated key
* there is an error in key decapsulation
* there is an error in decryption
 */

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg(feature = "base-mode-open")]
pub fn base_mode_open(
    config: Config,
    private_key: &[u8],
    encapped_key: &[u8],
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let Config { aead, kdf, kem } = config;

    let open = match aead {
        #[cfg(feature = "aead-aes-gcm-128")]
        Aead::AesGcm128 => match_kdf!(hpke::aead::AesGcm128, kdf, kem, open),
        #[cfg(feature = "aead-aes-gcm-256")]
        Aead::AesGcm256 => match_kdf!(hpke::aead::AesGcm256, kdf, kem, open),
        #[cfg(feature = "aead-chacha-20-poly-1305")]
        Aead::ChaCha20Poly1305 => match_kdf!(hpke::aead::ChaCha20Poly1305, kdf, kem, open),
    };

    open(private_key, ciphertext, encapped_key, info, aad)
}
