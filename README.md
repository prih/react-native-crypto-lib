# react-native-crypto-lib

crypto lib

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
const random_buffer = CryptoLib.randomBytes(32);

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
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
