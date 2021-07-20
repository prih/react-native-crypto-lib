# react-native-crypto-lib

crypto lib based on [trezor-firmware](https://github.com/trezor/trezor-firmware/tree/master/crypto).

## Installation

```sh
npm install react-native-crypto-lib
```

## Usage

```js
import CryptoLib, { HASH, HMAC } from 'react-native-crypto-lib';
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
const seed_buffer = await CryptoLib.mnemonicToSeed('words...', 'password (optional)');
const seed_buffer = CryptoLib.mnemonicToSeedSync('words...', 'password (optional)');
const mnemonic = CryptoLib.generateMnemonic(24);
const is_valid_mnemonic = CryptoLib.validateMnemonic('words...');
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
