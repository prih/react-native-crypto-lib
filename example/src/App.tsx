import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import CryptoLib from 'react-native-crypto-lib';
import type { Buffer } from 'buffer';

export default function App() {
  const [result, setResult] = React.useState<Buffer | undefined>();

  React.useEffect(() => {
    CryptoLib.randomBytes(32).then(setResult);
  }, []);

  return (
    <View style={styles.container}>
      <Text>Result: {result?.length}</Text>
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
