#[macro_export]
#[doc(hidden)]
macro_rules! match_algo {
    ($aead:ident, $kdf:ident, $kem:ident, $fn:ident) => { match_algo!(@aead, $aead, $kdf, $kem, $fn) };

    (@aead, $aead:ident, $kdf:ident, $kem:ident, $fn:ident) => {
        match $aead {
            #[cfg(feature = "aead-aes-gcm-128")]
            crate::Aead::AesGcm128 => match_algo!(@kdf, hpke::aead::AesGcm128, $kdf, $kem, $fn),
            #[cfg(feature = "aead-aes-gcm-256")]
            crate::Aead::AesGcm256 => match_algo!(@kdf, hpke::aead::AesGcm256, $kdf, $kem, $fn),
            #[cfg(feature = "aead-chacha-20-poly-1305")]
            crate::Aead::ChaCha20Poly1305 => {
                match_algo!(@kdf, hpke::aead::ChaCha20Poly1305, $kdf, $kem, $fn)
            }
        }
    };

    (@kdf, $aead:ty, $kdf:expr, $kem:expr, $fn:ident) => {
        match $kdf {
            #[cfg(feature = "kdf-sha256")]
            crate::Kdf::Sha256 => match_algo!(@kem, $aead, hpke::kdf::HkdfSha256, $kem, $fn),
            #[cfg(feature = "kdf-sha384")]
            crate::Kdf::Sha384 => match_algo!(@kem, $aead, hpke::kdf::HkdfSha384, $kem, $fn),
            #[cfg(feature = "kdf-sha512")]
            crate::Kdf::Sha512 => match_algo!(@kem, $aead, hpke::kdf::HkdfSha512, $kem, $fn),
        }
    };

    (@kem, $aead:ty, $kdf:ty, $kem:expr, $fn:ident) => {
        match $kem {
            #[cfg(feature = "kem-dh-p256-hkdf-sha256")]
            crate::Kem::DhP256HkdfSha256 => $fn::<$aead, $kdf, hpke::kem::DhP256HkdfSha256>,
            #[cfg(feature = "kem-x25519-hkdf-sha256")]
            crate::Kem::X25519HkdfSha256 => $fn::<$aead, $kdf, hpke::kem::X25519HkdfSha256>,
        }
    };

}
