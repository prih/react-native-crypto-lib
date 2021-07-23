import * as React from 'react';

import { StyleSheet, View, Text, Button } from 'react-native';
import { bip39, bip32 } from 'react-native-crypto-lib';
// import crypto from 'crypto';
// import * as bip39js from 'bip39';
// import { Buffer } from 'buffer';
import * as bip32js from 'bip32';

async function test1() {
  console.log('TEST1 start');

  // const key = await CryptoLib.randomBytes(64);
  // const data = await CryptoLib.randomBytes(256);
  const seed = await bip39.mnemonicToSeed(
    'resist unaware absent jazz pride will swift cigar soup journey doll come'
  );

  const t_start = new Date();
  const node = bip32.fromSeed(seed);
  for (let i = 0; i < 100; i++) {
    // await CryptoLib.pbkdf2(
    //   'Fg987h7fGjh9d7',
    //   'hmn9k8h9j8',
    //   100000,
    //   32,
    //   HMAC.SHA256
    // );

    // await bip39.mnemonicToSeed(
    //   'resist unaware absent jazz pride will swift cigar soup journey doll come'
    // );

    // const node = bip32.fromSeed(seed);
    node.derivePath(`m/44'/0'/0'/0/${i}`);
  }
  const t_end = new Date();

  return Number(t_end) - Number(t_start);
}

async function test2() {
  console.log('TEST2 start');

  // const key = await CryptoLib.randomBytes(64);
  // const data = await CryptoLib.randomBytes(256);
  const seed = await bip39.mnemonicToSeed(
    'resist unaware absent jazz pride will swift cigar soup journey doll come'
  );

  const t_start = new Date();
  const node = bip32js.fromSeed(seed);
  for (let i = 0; i < 100; i++) {
    // crypto.pbkdf2Sync('Fg987h7fGjh9d7', 'hmn9k8h9j8', 100000, 32, 'sha256');
    // await bip39js.mnemonicToSeed(
    //   'resist unaware absent jazz pride will swift cigar soup journey doll come'
    // );
    // const node = bip32js.fromSeed(seed);
    node.derivePath(`m/44'/0'/0'/0/${i}`);
  }
  const t_end = new Date();

  return Number(t_end) - Number(t_start);
}

export default function App() {
  const [result_time1, setResultTime1] = React.useState<number | undefined>();
  const [result_time2, setResultTime2] = React.useState<number | undefined>();

  return (
    <View style={styles.container}>
      <Button
        title="RUN"
        onPress={async () => {
          const t1 = await test1();
          setResultTime1(t1);
          const t2 = await test2();
          setResultTime2(t2);

          // const priv = secp256k1.randomPrivate();
          // const is_valid_priv = secp256k1.validatePrivate(priv);
          // const public33 = secp256k1.getPublic(priv);
          // const public65 = secp256k1.getPublic(priv, false);
          // const is_valid33 = secp256k1.validatePublic(public33);
          // const is_valid65 = secp256k1.validatePublic(public65);

          // console.log(is_valid_priv, is_valid33, is_valid65);

          // const ecdh = secp256k1.ecdh(
          //   Buffer.from(
          //     '03efd6b90f8196dda6478811d72f033420fb9aa503c69b5264304d78c4147786b4',
          //     'hex'
          //   ),
          //   Buffer.from(
          //     '314f788194461bdf6bc214a7e287a313c7be4b4326bf7e773aa1c7c41aca0789',
          //     'hex'
          //   ),
          //   true
          // );
          // console.log(ecdh.toString('hex'));

          // const seed = await bip39.mnemonicToSeed(
          //   'chase accident roof weather success loan frozen skirt chase supreme wrong ramp segment impose valve'
          // );

          // const root_node = bip32.fromSeed(seed);

          // const derive_node = root_node.derivePath(`m/44'/0'/0'/0/10`);
          // console.log('derive:', derive_node);
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
