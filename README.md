# Hybrid public key encryption with algorithms dispatched at runtime

This crate provides a generic-free interface to the [`hpke`][hpke]
crate, a rust implementation of the draft RFC9180 [hybrid public key
encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
scheme. If you know the specific (aead, kdf, kem) triple at compile
time, you should use the [`hpke`][hpke] crate directly.

Currently, this crate only exposes interfaces for the Base mode (0)
described in the hpke draft, and within base mode, only stateless
single-shot message encryption/decryption, as defined in [RFC9180§6][section-6].

The algorithms supported in this crate and their codepoints are as described in the [HPKE
specification][hpke-datatracker] and [draft-ietf-hpke-pq][hpke-pq].

[hpke]: https://github.com/rozbb/rust-hpke
[section-6]: https://www.rfc-editor.org/rfc/rfc9180.html#section-6
[hpke-datatracker]: https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/
[hpke-pq]: https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/

## Available cargo features:

`hpke-dispatch`'s cargo features are designed to align directly with those of [`hpke`][hpke]. See
that crate's documentation for discussion of how to selectively enable algorithms.

`hpke-dispatch` defines the following additional features:

* *algo-all*: enables all aead, kdf, and kem algorithms. Enabled by default.

* *aead-all*: Enables `aes` and `chacha` algorithm features. Enabled by default.

* *kdf-all*: Enables `hkdfsha2` and `shake` algorithm features. Enabled by default.

* *kem-all*: Enables `x25519`, `nistp` and `mlkem` algorithm features. Enabled by default.

* *serde*: enables derived serde serialization and deserialization for all public structs and enums.
  Disabled by default.

## Example feature usage:

To depend on this crate with all algorithms, use default features.

To depend on this crate with all algorithms and serde
enabled, but without `base-mode-seal`: `default-features = false,
features = ["algo-all", "base-mode-open", "serde"]`
