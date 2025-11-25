# Hybrid public key encryption with algorithms dispatched at runtime

This crate provides a generic-free interface to the [`hpke`][hpke]
crate, a rust implementation of the draft RFC9180 [hybrid public key
encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
scheme. If you know the specific (aead, kdf, kem) triple at compile
time, you should use the [`hpke`][hpke] crate directly.

Currently, this crate only exposes interfaces for the Base mode (0)
described in the hpke draft, and within base mode, only stateless
single-shot message encryption/decryption, as defined in [RFC9180§6][section-6]

[hpke]: https://github.com/rozbb/rust-hpke
[section-6]: https://www.rfc-editor.org/rfc/rfc9180.html#section-6

## Available cargo features:

* *base-mode-open*: Enables hpke base-mode one-shot open behavior
  (receiver functionality). Enabled by default.

* *base-mode-seal*: Enables hpke base-mode one-shot seal behavior
  (sender functionality). Enabled by default.

* *algo-all*: enables all aead, kdf, and kem algorithms. enabled by
  default.

* *aead-all*: Enables `aead-aes-gcm-128`, `aead-aes-gcm-256`, and
  `aead-chacha-20-poly-1305` algorithm features. Enabled by default.

* *kdf-all*: Enables `kdf-sha256`, `kdf-sha384`, `kdf-sha512`
  algorithm features. Enabled by default.

* *kem-all*: Enables `kem-dh-p256-hkdf-sha256`,
  `kem-dh-p384-hkdf-sha384`, `kem-dh-p521-hkdf-sha512`, and
  `kem-x25519-hkdf-sha256` algorithm features. Enabled by default.

* *serde*: enables derived serde serialization and deserialization for
  all public structs and enums. Disabled by default.

## Example feature usage:

To depend on this crate with all algorithms,
`base-mode-open`, and `base-mode-seal`, use default features.

To depend on this crate with all algorithms and serde
enabled, but without `base-mode-seal`: `default-features = false,
features = ["algo-all", "base-mode-open", "serde"]`
