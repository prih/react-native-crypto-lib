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
import {
  rand,
  digest,
  bip39,
  secp256k1,
  bip32
} from 'react-native-crypto-lib';

// ...

const random_uint32 = rand.randomNumber();
const random_buffer = await rand.randomBytes(32);
const random_buffer = rand.randomBytesSync(32);

// sha2
const sha1_buffer = digest.createHash('sha1', data);
const sha256_buffer = digest.createHash('sha256', data);
const sha512_buffer = digest.createHash('sha512', data);

// sha3
const sha3_256_buffer = digest.createHash('sha3_256', data);
const sha3_512_buffer = digest.createHash('sha3_512', data);
const keccak_256_buffer = digest.createHash('keccak256', data);
const keccak_512_buffer = digest.createHash('keccak512', data);

// ripemd160
const ripemd160_buffer = digest.createHash('ripemd160', data);
const ripemd160_buffer = digest.createHash('rmd160', data);

// hash256
const hash256_buffer = digest.createHash('hash256', data);

// hash160
const hash160_buffer = digest.createHash('hash160', data);

// HMAC
const hmac256_buffer = digest.createHmac('sha256', key, data);
const hmac512_buffer = digest.createHmac('sha512', key, data);

// pbkdf2
const pbkdf2_256_buffer = await digest.pbkdf2(pass, salt, 10000, 32, 'sha256');
const pbkdf2_512_buffer = await digest.pbkdf2(pass, salt, 10000, 32, 'sha512');

// pbkdf2Sync
const pbkdf2_256_buffer = digest.pbkdf2Sync(pass, salt, 10000, 32, 'sha256');
const pbkdf2_512_buffer = digest.pbkdf2Sync(pass, salt, 10000, 32, 'sha512');

// BIP39
const seed_buffer = await bip39.mnemonicToSeed('words...', 'password (optional)');
const seed_buffer = bip39.mnemonicToSeedSync('words...', 'password (optional)');
const mnemonic = bip39.generateMnemonic(24);
const is_valid_mnemonic = bip39.validateMnemonic('words...');

// ECDSA/ECDH secp256k1
const priv = secp256k1.randomPrivate();
const is_valid_priv = secp256k1.validatePrivate(priv);
const public33 = secp256k1.getPublic(priv);
const public65 = secp256k1.getPublic(priv, false);
const public33 = secp256k1.readPublic(public65, true);
const is_valid33 = secp256k1.validatePublic(public33);
const is_valid65 = secp256k1.validatePublic(public65);
const public33 = secp256k1.recover(sig, msg, recid, true);
const public65 = secp256k1.recover(sig, msg, recid, false);
const ecdh_sha256 = secp256k1.ecdh(pub, priv);
const ecdh_sha256 = secp256k1.ecdh(pub, priv, true, HASH.SHA256);
const ecdh_compact = secp256k1.ecdh(pub, priv, true, undefined);
const ecdh_xy = secp256k1.ecdh(pub, priv, false, undefined);
const is_verif = secp256k1.verify(pub, sig, msg);
const sig = await secp256k1.sign(priv, msg);
const sig = secp256k1.signSync(priv, msg);

// BIP32
const node = bip32.fromSeed(seed_buffer);
const node = bip32.fromKeyLocal(priv, pub, chain_code, depth, index, parentFingerprint);
const addr = node.derivePath(`m/44'/0'/0'/0/0`);
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
