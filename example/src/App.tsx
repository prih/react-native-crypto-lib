import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import CryptoLib, { HASH, HMAC } from 'react-native-crypto-lib';
import { Buffer } from 'buffer';

const data = Buffer.from('Hello World');

export default function App() {
  const [result_hash, setResultHash] = React.useState<Buffer | undefined>();
  const [result_hmac, setResultHmac] = React.useState<Buffer | undefined>();

  React.useEffect(() => {
    CryptoLib.hash(HASH.SHA256, data).then(setResultHash);
  }, []);

  React.useEffect(() => {
    const key = Buffer.from('0001020304050607');
    CryptoLib.hmac(HMAC.SHA256, key, data).then(setResultHmac);
  }, []);

  return (
    <View style={styles.container}>
      <Text>HASH: {result_hash?.toString('hex')}</Text>
      <Text>HMAC: {result_hmac?.toString('hex')}</Text>
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
