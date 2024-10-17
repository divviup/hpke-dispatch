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

## WebAssembly ready

This crate is also published to npm as [`hpke`][npm] as a
typescript/javascript package, and can also be custom built for
specific wasm use cases (omitting unused algorithms) with
[`wasm-pack`][wasm-pack]. For an example of using the library from
node, see [examples/example.ts][example-ts]

[npm]: https://www.npmjs.com/package/hpke
[wasm-pack]: https://github.com/rustwasm/wasm-pack
[example-ts]: https://github.com/jbr/hpke-dispatch/blob/main/examples/example.ts

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


