import { NativeModules } from 'react-native';

type CryptoLibType = {
  multiply(a: number, b: number): Promise<number>;
};

const { CryptoLib } = NativeModules;

export default CryptoLib as CryptoLibType;
