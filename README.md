# react-native-crypto-lib

crypto lib based on [trezor-firmware](https://github.com/trezor/trezor-firmware/tree/master/crypto).

## Installation

```sh
npm install react-native-crypto-lib
```

### iOS

```sh
cd ios && pod install && cd -
```

## Usage

```js
import CryptoLib, {
  HASH,
  HMAC,
  bip39,
  secp256k1
} from 'react-native-crypto-lib';
import { Buffer } from 'buffer';

// ...

const data = Buffer.from('Hello World', 'hex');

const random_uint32 = CryptoLib.randomNumber();
const random_buffer = await CryptoLib.randomBytes(32);
const random_buffer = CryptoLib.randomBytesSync(32);

// sha2
const sha1_buffer = CryptoLib.hash(HASH.SHA1, data);
const sha256_buffer = CryptoLib.hash(HASH.SHA256, data);
const sha512_buffer = CryptoLib.hash(HASH.SHA512, data);

// sha3
const sha3_256_buffer = CryptoLib.hash(HASH.SHA3_256, data);
const sha3_512_buffer = CryptoLib.hash(HASH.SHA3_512, data);
const keccak_256_buffer = CryptoLib.hash(HASH.KECCAK_256, data);
const keccak_512_buffer = CryptoLib.hash(HASH.KECCAK_512, data);

// ripemd160
const ripemd160_buffer = CryptoLib.hash(HASH.RIPEMD160, data);

// HMAC
const hmac_key = Buffer.from('0102030405060708', 'hex');

const hmac256_buffer = CryptoLib.hmac(HMAC.SHA256, hmac_key, data);
const hmac512_buffer = CryptoLib.hmac(HMAC.SHA512, hmac_key, data);

// pbkdf2
const pbkdf2_256_buffer = await CryptoLib.pbkdf2('password', 'salt', 10000, 32, HMAC.SHA256);
const pbkdf2_512_buffer = await CryptoLib.pbkdf2('password', 'salt', 10000, 32, HMAC.SHA512);

// pbkdf2Sync
const pbkdf2_256_buffer = CryptoLib.pbkdf2Sync('password', 'salt', 10000, 32, HMAC.SHA256);
const pbkdf2_512_buffer = CryptoLib.pbkdf2Sync('password', 'salt', 10000, 32, HMAC.SHA512);

// BIP39
const seed_buffer = await bip39.mnemonicToSeed('words...', 'password (optional)');
const seed_buffer = bip39.mnemonicToSeedSync('words...', 'password (optional)');
const mnemonic = bip39.generateMnemonic(24);
const is_valid_mnemonic = bip39.validateMnemonic('words...');

// secp256k1 ECDSA/ECDH
const priv = secp256k1.randomPrivate();
const is_valid_priv = secp256k1.validatePrivate(priv);
const public33 = secp256k1.getPublic(priv);
const public65 = secp256k1.getPublic(priv, false);
const is_valid33 = secp256k1.validatePublic(public33);
const is_valid65 = secp256k1.validatePublic(public65);
const public33 = secp256k1.recover(sig, digest, recid, true);
const public65 = secp256k1.recover(sig, digest, recid, false);
const ecdh_sha256 = secp256k1.ecdh(pub, priv);
const ecdh_sha256 = secp256k1.ecdh(pub, priv, true, HASH.SHA256);
const ecdh_compact = secp256k1.ecdh(pub, priv, true, undefined);
const ecdh_xy = secp256k1.ecdh(pub, priv, false, undefined);
const is_verif = secp256k1.verify(pub, sig, digest);
const sig = await secp256k1.sign(priv, digest);
const sig = secp256k1.signSync(priv, digest);
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
