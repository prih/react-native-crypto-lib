import * as React from 'react';

import { StyleSheet, View, Text, Button } from 'react-native';
import { digest, bip39, bip32 } from 'react-native-crypto-lib';
import * as bip39js from 'bip39';
import * as bip32js from 'bip32';
import { Buffer } from 'buffer';
import bs58 from 'bs58';

const network_options = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'tb',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
};

function createXpub(node: bip32.BIP32, network: any) {
  const pub = node?.publicKey;
  const bip32pub = network?.bip32?.public;

  if (!pub || !bip32pub) {
    throw new Error('xpub error');
  }

  const buffer = Buffer.allocUnsafe(78);
  buffer.writeUInt32BE(bip32pub, 0);
  buffer.writeUInt8(node.depth, 4);
  // buffer.writeUInt32BE(node.parentFingerprint, 5);
  node.parentFingerprint?.copy(buffer, 5);
  buffer.writeUInt32BE(node.index, 9);
  node.chainCode.copy(buffer, 13);
  node.publicKey?.copy(buffer, 45);

  const check_hash = digest.createHash('hash256', buffer);

  return bs58.encode(Buffer.concat([buffer, check_hash.slice(0, 4)]));
}

async function test1() {
  console.log('TEST1 start');
  const seed = await bip39.mnemonicToSeed('');

  console.log('seed:', seed.toString('hex'));

  const node = bip32.fromSeed(seed);
  console.log(
    'root:',
    node.privateKey?.toString('hex'),
    node.publicKey?.toString('hex'),
    node.chainCode.toString('hex'),
    node.depth,
    node.index,
    node.parentFingerprint,
    node.fingerprint
  );

  const addr = node.derivePath(`m/44'/1'/0'`);
  console.log(
    'addr:',
    addr.privateKey?.toString('hex'),
    addr.publicKey?.toString('hex'),
    addr.chainCode.toString('hex'),
    addr.depth,
    addr.index,
    addr.parentFingerprint,
    addr.fingerprint
  );

  console.log('xpub:', createXpub(addr, network_options));
}

async function test2() {
  console.log('TEST2 start');

  const seed = await bip39js.mnemonicToSeed('');

  console.log('seed:', seed.toString('hex'));

  const node = bip32js.fromSeed(seed, network_options);
  console.log(
    'root:',
    node.privateKey?.toString('hex'),
    node.publicKey?.toString('hex'),
    node.chainCode.toString('hex'),
    node.depth,
    node.index,
    node.parentFingerprint,
    node.fingerprint
  );

  const addr = node.derivePath(`m/44'/1'/0'`);
  console.log(
    'addr:',
    addr.privateKey?.toString('hex'),
    addr.publicKey?.toString('hex'),
    addr.chainCode.toString('hex'),
    addr.depth,
    addr.index,
    addr.parentFingerprint,
    addr.fingerprint
  );

  console.log('xpub:', addr.neutered().toBase58());
}

export default function App() {
  const [result_time1, setResultTime1] = React.useState<number | undefined>();
  const [result_time2, setResultTime2] = React.useState<number | undefined>();

  return (
    <View style={styles.container}>
      <Button
        title="RUN"
        onPress={async () => {
          await test1();
          setResultTime1(0);
          await test2();
          setResultTime2(0);
        }}
      />
      <Text>Result Native: {result_time1}</Text>
      <Text>Result JS: {result_time2}</Text>
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
