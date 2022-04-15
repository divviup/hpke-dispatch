use hpke::{
    single_shot_open, single_shot_seal, Deserializable, OpModeR::Base as BaseRecip,
    OpModeS::Base as BaseSend, Serializable,
};
use num_enum::TryFromPrimitive;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(feature = "serde", derive(serde_crate::Serialize, serde_crate::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum Aead {
    #[cfg(feature = "aead-aes-gcm-128")]
    AesGcm128 = 1,
    #[cfg(feature = "aead-aes-gcm-256")]
    AesGcm256 = 2,
    #[cfg(feature = "aead-chacha-20-poly-1305")]
    ChaCha20Poly1305 = 3,
}

#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(feature = "serde", derive(serde_crate::Serialize, serde_crate::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum Kdf {
    #[cfg(feature = "kdf-sha256")]
    Sha256 = 1,
    #[cfg(feature = "kdf-sha384")]
    Sha384 = 2,
    #[cfg(feature = "kdf-sha512")]
    Sha512 = 3,
}

#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(feature = "serde", derive(serde_crate::Serialize, serde_crate::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum Kem {
    #[cfg(feature = "kem-dh-p256-hkdf-sha256")]
    DhP256HkdfSha256 = 10,
    #[cfg(feature = "kem-x25519-hkdf-sha256")]
    X25519HkdfSha256 = 20,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(feature = "serde", derive(serde_crate::Serialize, serde_crate::Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Config {
    pub aead: Aead,
    pub kdf: Kdf,
    pub kem: Kem,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Config {
    pub fn base_mode_seal(
        self,
        pk_recip: &[u8],
        info: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncappedKeyAndCiphertext, HpkeError> {
        base_mode_seal(self, pk_recip, info, plaintext, aad)
    }

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

#[derive(Copy, Clone, Debug)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(feature = "serde", derive(serde_crate::Serialize, serde_crate::Deserialize))]
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
    pub fn try_from_ids(aead_id: u16, kdf_id: u16, kem_id: u16) -> Result<Config, IdLookupError> {
        Ok(Self {
            aead: aead_id.try_into().map_err(|_| IdLookupError)?,
            kdf: kdf_id.try_into().map_err(|_| IdLookupError)?,
            kem: kem_id.try_into().map_err(|_| IdLookupError)?,
        })
    }
}

fn from_bytes<T: Deserializable>(encoded: &[u8]) -> Result<T, HpkeError> {
    Ok(T::from_bytes(encoded)?)
}

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
    let mut csprng = rand::thread_rng();
    let (encapped_key, ciphertext) = single_shot_seal::<AeadT, KdfT, KemT, _>(
        &BaseSend,
        &from_bytes(pk_recip)?,
        info,
        plaintext,
        aad,
        &mut csprng,
    )?;

    Ok(EncappedKeyAndCiphertext {
        encapped_key: encapped_key.to_bytes().to_vec(),
        ciphertext,
    })
}

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
    Ok(single_shot_open::<AeadT, KdfT, KemT>(
        &BaseRecip,
        &from_bytes(private_key)?,
        &from_bytes(encapped_key)?,
        info,
        &ciphertext,
        aad,
    )?)
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
        pub struct EncappedKeyAndCiphertext {
            encapped_key: Vec<u8>,
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
        pub struct EncappedKeyAndCiphertext {
            pub encapped_key: Vec<u8>,
            pub ciphertext: Vec<u8>
        }

        pub use hpke::HpkeError;
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl EncappedKeyAndCiphertext {
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(getter)]
    pub fn encapped_key(&self) -> Vec<u8> {
        self.encapped_key.clone()
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn encapped_key(&self) -> &[u8] {
        &self.encapped_key
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
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
