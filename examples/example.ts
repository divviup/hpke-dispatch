import { Keypair, Aead, Kdf, Kem, Config } from "hpke";

let config = Config.try_from_ids(
  Aead.AesGcm128,
  Kdf.Sha256,
  Kem.DhP256HkdfSha256
);
let keypair = new Keypair(config.kem);
let publicKey = keypair.public_key;
let privateKey = keypair.private_key;

var enc = new TextEncoder();
let aad = enc.encode("associated data");
let plaintext = enc.encode("plaintext message text");
let info = enc.encode("app info");
let keyAndCiphertext = config.base_mode_seal(publicKey, info, plaintext, aad);
let encapsulatedKey = keyAndCiphertext.encapped_key;
let ciphertext = keyAndCiphertext.ciphertext;

let roundTrip = config.base_mode_open(
  privateKey,
  encapsulatedKey,
  info,
  ciphertext,
  aad
);

let dec = new TextDecoder();
console.log(dec.decode(roundTrip));
