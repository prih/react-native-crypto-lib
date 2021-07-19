# react-native-crypto-lib

crypto lib

## Installation

```sh
npm install react-native-crypto-lib
```

## Usage

```js
import CryptoLib from "react-native-crypto-lib";
import { Buffer } from 'buffer';

// ...

const random_uint32 = await CryptoLib.randomNumber();

const random_buffer = await CryptoLib.randomBytes(32);

const sha1_buffer = await CryptoLib.sha1(Buffer.from('Hello World'));
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
