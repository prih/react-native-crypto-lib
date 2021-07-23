import * as React from 'react';

import { StyleSheet, View, Text, Button } from 'react-native';
import { bip39, bip32 } from 'react-native-crypto-lib';
import * as bip32js from 'bip32';

async function test1() {
  console.log('TEST1 start');
  const seed = await bip39.mnemonicToSeed(
    'resist unaware absent jazz pride will swift cigar soup journey doll come'
  );

  const t_start = new Date();
  const node = bip32.fromSeed(seed);
  for (let i = 0; i < 100; i++) {
    node.derivePath(`m/44'/0'/0'/0/${i}`);
  }
  const t_end = new Date();

  return Number(t_end) - Number(t_start);
}

async function test2() {
  console.log('TEST2 start');

  const seed = await bip39.mnemonicToSeed(
    'resist unaware absent jazz pride will swift cigar soup journey doll come'
  );

  const t_start = new Date();
  const node = bip32js.fromSeed(seed);
  for (let i = 0; i < 100; i++) {
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
