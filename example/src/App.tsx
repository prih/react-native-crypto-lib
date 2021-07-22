import * as React from 'react';

import { StyleSheet, View, Text, Button } from 'react-native';
import CryptoLib from 'react-native-crypto-lib';
// import crypto from 'crypto';
import * as bip39 from 'bip39';
import { Buffer } from 'buffer';

async function test1() {
  console.log('TEST1 start');

  // const key = await CryptoLib.randomBytes(64);
  // const data = await CryptoLib.randomBytes(256);

  const t_start = new Date();
  for (let i = 0; i < 1; i++) {
    // await CryptoLib.pbkdf2(
    //   'Fg987h7fGjh9d7',
    //   'hmn9k8h9j8',
    //   100000,
    //   32,
    //   HMAC.SHA256
    // );

    await CryptoLib.mnemonicToSeed(
      'resist unaware absent jazz pride will swift cigar soup journey doll come'
    );
  }
  const t_end = new Date();

  return Number(t_end) - Number(t_start);
}

async function test2() {
  console.log('TEST2 start');

  // const key = await CryptoLib.randomBytes(64);
  // const data = await CryptoLib.randomBytes(256);

  const t_start = new Date();
  for (let i = 0; i < 1; i++) {
    // crypto.pbkdf2Sync('Fg987h7fGjh9d7', 'hmn9k8h9j8', 100000, 32, 'sha256');
    await bip39.mnemonicToSeed(
      'resist unaware absent jazz pride will swift cigar soup journey doll come'
    );
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

          const priv = CryptoLib.ecdsaRandomPrivate();
          const is_valid_priv = CryptoLib.ecdsaValidatePrivate(priv);
          const public33 = CryptoLib.ecdsaGetPublic(priv);
          const public65 = CryptoLib.ecdsaGetPublic(priv, false);
          const is_valid33 = CryptoLib.ecdsaValidatePublic(public33);
          const is_valid65 = CryptoLib.ecdsaValidatePublic(public65);

          console.log(is_valid_priv, is_valid33, is_valid65);

          const pub_rec = CryptoLib.ecdsaRecover(
            Buffer.from(
              '320d39ee6258f6b912307994ba603b9522ead3af2790b0eed23e6cade7d86125099300e015a6acaff1a9dbd96d57a1892e47d76211d13e6f235fd1a26e3c5c09',
              'hex'
            ),
            Buffer.from(
              '423840043a1d6ec96381259c34b66cc98264b3ebe3b663c12a888705a588496e',
              'hex'
            ),
            0,
            true
          );
          console.log(pub_rec.toString('hex'));
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
