macro_rules! match_algo {
    ($aead:ident, $kdf:ident, $kem:ident, $fn:ident) => {
        match_algo!(@aead, $aead, $kdf, $kem, $fn)
    };

    (@aead, $aead:ident, $kdf:ident, $kem:ident, $fn:ident) => {
        match $aead {
            #[cfg(feature = "aes")]
            $crate::Aead::AesGcm128 => match_algo!(@kdf, hpke::aead::AesGcm128, $kdf, $kem, $fn),
            #[cfg(feature = "aes")]
            $crate::Aead::AesGcm256 => match_algo!(@kdf, hpke::aead::AesGcm256, $kdf, $kem, $fn),
            #[cfg(feature = "chacha")]
            $crate::Aead::ChaCha20Poly1305 => {
                match_algo!(@kdf, hpke::aead::ChaCha20Poly1305, $kdf, $kem, $fn)
            }
        }
    };

    (@kdf, $aead:ty, $kdf:expr, $kem:expr, $fn:ident) => {
        match $kdf {
            #[cfg(feature = "hkdfsha2")]
            $crate::Kdf::Sha256 => match_algo!(@kem, $aead, hpke::kdf::HkdfSha256, $kem, $fn),
            #[cfg(feature = "hkdfsha2")]
            $crate::Kdf::Sha384 => match_algo!(@kem, $aead, hpke::kdf::HkdfSha384, $kem, $fn),
            #[cfg(feature = "hkdfsha2")]
            $crate::Kdf::Sha512 => match_algo!(@kem, $aead, hpke::kdf::HkdfSha512, $kem, $fn),
            #[cfg(feature = "shake")]
            $crate::Kdf::Shake128 => match_algo!(@kem, $aead, hpke::kdf::KdfShake128, $kem, $fn),
            #[cfg(feature = "shake")]
            $crate::Kdf::Shake256 => match_algo!(@kem, $aead, hpke::kdf::KdfShake256, $kem, $fn),
            #[cfg(feature = "shake")]
            $crate::Kdf::TurboShake128 => match_algo!(
                @kem,
                $aead,
                hpke::kdf::KdfTurboShake128,
                $kem,
                $fn
            ),
            #[cfg(feature = "shake")]
            $crate::Kdf::TurboShake256 => match_algo!(
                @kem,
                $aead,
                hpke::kdf::KdfTurboShake256,
                $kem,
                $fn
            ),
        }
    };

    (@kem, $aead:ty, $kdf:ty, $kem:expr, $fn:ident) => {
        match $kem {
            #[cfg(feature = "nistp")]
            $crate::Kem::DhP256HkdfSha256 => $fn::<$aead, $kdf, hpke::kem::DhP256HkdfSha256>,
            #[cfg(feature = "nistp")]
            $crate::Kem::DhP384HkdfSha384 => $fn::<$aead, $kdf, hpke::kem::DhP384HkdfSha384>,
            #[cfg(feature = "nistp")]
            $crate::Kem::DhP521HkdfSha512 => $fn::<$aead, $kdf, hpke::kem::DhP521HkdfSha512>,
            #[cfg(feature = "x25519")]
            $crate::Kem::X25519HkdfSha256 => $fn::<$aead, $kdf, hpke::kem::X25519HkdfSha256>,
            #[cfg(feature = "mlkem")]
            $crate::Kem::MlKem768 => $fn::<$aead, $kdf, hpke::kem::MlKem768>,
            #[cfg(feature = "mlkem")]
            $crate::Kem::MlKem1024 => $fn::<$aead, $kdf, hpke::kem::MlKem1024>,
            #[cfg(all(feature = "mlkem", feature = "x25519"))]
            $crate::Kem::XWing => $fn::<$aead, $kdf, hpke::kem::XWing>,
            #[cfg(all(feature = "mlkem", feature = "nistp"))]
            $crate::Kem::MlKem768P256 => $fn::<$aead, $kdf, hpke::kem::MlKem768P256>,
            #[cfg(all(feature = "mlkem", feature = "nistp"))]
            $crate::Kem::MlKem1024P384 => $fn::<$aead, $kdf, hpke::kem::MlKem1024P384>,
        }
    };
}
