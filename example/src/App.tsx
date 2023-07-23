import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import {
  rng,
  digest,
  bip39,
  bip32,
  // ecdsa,
} from 'react-native-crypto-lib';
import { Buffer } from 'buffer';

async function test() {
  const hmac_key = Buffer.from('01020304050607080102030405060708', 'hex');
  const data = Buffer.from(
    'ab7615a6cb35f59c2c0a2e9d51d2bf2f20366b0fc1e27a30e3e25cfd65b5f5c3',
    'hex'
  );

  // rng
  const rng1 = await rng.randomBytes(32);
  if (rng1.length !== 32) {
    throw new Error('rng');
  }

  // sha1
  const sha1 = digest.createHash(digest.HASH.SHA1, data);
  if (sha1.toString('hex') !== 'c0f2de4e4789d20d4d6126d9db98f82cfab0cf9f') {
    throw new Error('sha1');
  }
  // sha256
  const sha256 = digest.createHash(digest.HASH.SHA256, data);
  if (
    sha256.toString('hex') !==
    '2b7a10b97999f4b4ed3548412049c722cb5e518ac724ab279f876b1bba657e59'
  ) {
    throw new Error('sha256');
  }
  // sha512
  const sha512 = digest.createHash(digest.HASH.SHA512, data);
  if (
    sha512.toString('hex') !==
    '33f3b9592d7ef029360da0e161a3494f8b0f5ce1b1d0d1a582621cd3b9ed5ec1170a489d307f1bae8752f670092e0c4795be5465b65b5a24f3e5e64277b3b458'
  ) {
    throw new Error('sha512');
  }
  // sha3_256
  const sha3_256 = digest.createHash(digest.HASH.SHA3_256, data);
  if (
    sha3_256.toString('hex') !==
    'b75558da7d6d3ed41ce1c63164f4a3060129523749f15ebe47dfaba2a10e1f38'
  ) {
    throw new Error('sha3_256');
  }
  // sha3_512
  const sha3_512 = digest.createHash(digest.HASH.SHA3_512, data);
  if (
    sha3_512.toString('hex') !==
    'b922d2753671284dd9886802d76f754c7f8e5ab8e2072f2830f684ea9a6a0d8a9b269f0b336ff566a3c9dcdb438ed1b3e9bef32d0da3b0ae868d4dbedc048c95'
  ) {
    throw new Error('sha3_512');
  }
  // keccak_256
  const keccak_256 = digest.createHash(digest.HASH.KECCAK256, data);
  if (
    keccak_256.toString('hex') !==
    '9dab2885dacf7b470d2ec9f8122a865ad3870ec0c022ff9c96164d188c493172'
  ) {
    throw new Error('keccak_256');
  }
  // keccak_512
  const keccak_512 = digest.createHash(digest.HASH.KECCAK512, data);
  if (
    keccak_512.toString('hex') !==
    'a79fe6911bc62bbc85002fd18c255a5aa848bf4b3ee74b341f31e2d9f5871bf9cf398cad6b8dd7303a5bdb9990e0dab6ec257f61719145ab81ef3f43b4691b5b'
  ) {
    throw new Error('keccak_512');
  }
  // ripemd160
  const ripemd160 = digest.createHash(digest.HASH.RIPEMD160, data);
  if (
    ripemd160.toString('hex') !== '8017d0a5b14f9fe36ef2bf0e2a93c110f56ff2cb'
  ) {
    throw new Error('ripemd160');
  }
  // hash256
  const hash256 = digest.createHash(digest.HASH.HASH256, data);
  if (
    hash256.toString('hex') !==
    '7b13aa30b329440754ac068dc78f35c1d107412d7994e55342ecaf475a3ea77c'
  ) {
    throw new Error('hash256');
  }
  // hash160
  const hash160 = digest.createHash(digest.HASH.HASH160, data);
  if (hash160.toString('hex') !== 'ba07b51bb6ff46e578ce24f0e885004c9669ae09') {
    throw new Error('hash160');
  }

  // hmac_sha256
  const hmac_sha256 = digest.createHmac(
    digest.HMAC_HASH.SHA256,
    hmac_key,
    data
  );
  if (
    hmac_sha256.toString('hex') !==
    '4d459f295a8bde2584e808eb5bcad46acdc4a8f82b1baf0b4876b51f16640143'
  ) {
    throw new Error('hmac_sha256');
  }
  // hmac_sha512
  const hmac_sha512 = digest.createHmac(
    digest.HMAC_HASH.SHA512,
    hmac_key,
    data
  );
  if (
    hmac_sha512.toString('hex') !==
    '97b90cc8a141601399d4ac188ca54fd4ab1c99eb27077ff17a6d4133a77a71b2a5b05f8ba2acae3368caa9933ebe1ca7ad9ce0eb43f5930c9c7d2f03b6d20ad9'
  ) {
    throw new Error('hmac_sha512');
  }

  // pbkdf2_sha256
  const pbkdf2_sha256 = await digest.pbkdf2(
    'password',
    hmac_key,
    100000,
    32,
    digest.PBKDF2_HASH.SHA256
  );
  if (
    pbkdf2_sha256.toString('hex') !==
    '5beee544034b93c8e66fbc8a9781047f3a0ceedfa5d0e755a728a8b0f833203f'
  ) {
    throw new Error('pbkdf2_sha256');
  }
  // pbkdf2_sha512
  const pbkdf2_sha512 = await digest.pbkdf2(
    'password',
    hmac_key,
    100000,
    64,
    digest.PBKDF2_HASH.SHA512
  );
  if (
    pbkdf2_sha512.toString('hex') !==
    '4f78af69c8e31ab0c4fc9e51fd5f0b8e467da91cb942109e74c9ba1fa98374a1c4f549b7d531df73acd32603c85f2895268f2586c80f536601b6a029a7ac5607'
  ) {
    throw new Error('pbkdf2_sha512');
  }

  // bip39-generateMnemonic-12
  const mnem1 = await bip39.generateMnemonic(128);
  if (mnem1.split(' ').length !== 12) {
    throw new Error('bip39.generateMnemonic 12');
  }
  // bip39-generateMnemonic-24
  const mnem2 = await bip39.generateMnemonic(256);
  if (mnem2.split(' ').length !== 24) {
    throw new Error('bip39.generateMnemonic 24');
  }
  // bip39-mnemonicToSeed
  const seed1 = await bip39.mnemonicToSeed(
    'awake book subject inch gentle blur grant damage process float month clown'
  );
  if (
    seed1.toString('hex') !==
    '747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03'
  ) {
    throw new Error('bip39-mnemonicToSeed');
  }
  // bip39-mnemonicToSeed-pwd
  const seed2 = await bip39.mnemonicToSeed(
    'awake book subject inch gentle blur grant damage process float month clown',
    'password'
  );
  if (
    seed2.toString('hex') !==
    '77e4835ac627adf013c2d6ecad2c4042c34097ee1df811988d3658881666b214b60a6b8cea5775550adbfd002c01180321bdaef97ac684049b6bc88c422d9154'
  ) {
    throw new Error('bip39-mnemonicToSeed-pwd');
  }
  // bip39-validateMnemonic-valid
  const seed1_valid = await bip39.validateMnemonic(
    'awake book subject inch gentle blur grant damage process float month clown'
  );
  if (!seed1_valid) {
    throw new Error('bip39-validateMnemonic-valid');
  }
  // bip39-validateMnemonic-invalid
  const seed1_invalid = await bip39.validateMnemonic(
    'awake book subject inch gentle blur grant damage process float month month'
  );
  if (seed1_invalid) {
    throw new Error('bip39-validateMnemonic-invalid');
  }

  const bip32_node = bip32.hdNodeFromSeed(
    'secp256k1',
    Buffer.from(
      '9e742e93328b891970240a21297e2b076ee0cfd2ff150f80b56d2885cbe5cd77a52b79bbef02fd6fba94283240281e2784b8e8c325a21cf8658adbcd3889c06f',
      'hex'
    )
  );
  if (
    bip32_node.depth !== 0 ||
    bip32_node.child_num !== 0 ||
    bip32_node.private_key !== 'ZGAThuyG3DDvkK0BUnl20Sr1jI1Ze1EqDJIG2xJU7z0=' ||
    bip32_node.public_key !== 'Awd8EmgQwUezwdBpf4JW6t7QUVs5U2+DdCn5nNh8G0lp' ||
    bip32_node.chain_code !== 'zlKwdxHt5jH3iko4D+g/OPjLeuJXN3jh6EX//TxyIxk=' ||
    bip32_node.fingerprint !== 711613981
  ) {
    throw new Error('bip32.hdNodeFromSeed');
  }

  const bip32_node0 = bip32.derivePath(bip32_node, `m/44'/1'/0'`);
  if (
    bip32_node0.depth !== 3 ||
    bip32_node0.child_num !== 2147483648 ||
    bip32_node0.private_key !==
      'TOem0Fpx7oNurlk6ftIRmtaAW9uqQXqhPrTOdfScpBA=' ||
    bip32_node0.public_key !== 'A9V+R3SOn0FNw0kiYVXIPsYgK1VQ9Q2NeOrDPxnqkBUv' ||
    bip32_node0.chain_code !== 'cjrgdzmStpkkGqtXsuNBwWxgSbB8MY1Vn37SB1GHy0g=' ||
    bip32_node0.fingerprint !== 2687989489
  ) {
    throw new Error('bip32.derivePath');
  }

  const bip32_child = bip32.derivePath(
    {
      ...bip32_node0,
      private_derive: false,
    },
    `0/0`
  );
  if (
    bip32_child.depth !== 5 ||
    bip32_child.child_num !== 0 ||
    bip32_child.public_key !== 'AwtbcMGyfFug7TbGMppktwqd8WyG11j1gKr2BgtNwcLf' ||
    bip32_child.chain_code !== 'AeqQDr8EsHQWmxwDvju+G9uVF5ETxLttF7n9mw0qWE0=' ||
    bip32_child.fingerprint !== 584842416
  ) {
    throw new Error('bip32.derivePath');
  }

  // console.log(await (await ecdsa.ecdsaRandomPrivate()).toString('hex'));
}

export default function App() {
  const [result, setResult] = React.useState<number | string | undefined>();

  React.useEffect(() => {
    test()
      .then(() => {
        setResult('OK');
      })
      .catch((err) => {
        console.error(err);
      });
  }, []);

  return (
    <View style={styles.container}>
      <Text>Test: {result}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
