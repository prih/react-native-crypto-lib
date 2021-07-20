import * as React from 'react';

import { StyleSheet, View, Text, Button } from 'react-native';
import CryptoLib, { HMAC } from 'react-native-crypto-lib';
// import { Buffer } from 'buffer';
import crypto from 'crypto';

async function test1() {
  console.log('TEST1 start');

  const key = await CryptoLib.randomBytes(64);
  const data = await CryptoLib.randomBytes(256);

  const t_start = new Date();
  for (let i = 0; i < 100000; i++) {
    CryptoLib.hmac(HMAC.SHA512, key, data);
  }
  const t_end = new Date();

  return Number(t_end) - Number(t_start);
}

async function test2() {
  console.log('TEST2 start');

  const key = await CryptoLib.randomBytes(64);
  const data = await CryptoLib.randomBytes(256);

  const t_start = new Date();
  for (let i = 0; i < 100000; i++) {
    crypto.createHmac('sha512', key).update(data).digest();
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
