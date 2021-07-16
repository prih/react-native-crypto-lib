import { NativeModules } from 'react-native';

type CryptoLibType = {
  randomNumber(): Promise<number>;
};

const { CryptoLib } = NativeModules;

export default CryptoLib as CryptoLibType;
