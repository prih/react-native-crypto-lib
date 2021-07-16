import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

type CryptoLibType = {
  randomNumber(): Promise<number>;
  randomBytes(length: number): Promise<Buffer>;
};

const { CryptoLib } = NativeModules;

const CryptoLibJs = {
  randomNumber: CryptoLib.randomNumber,
  randomBytes: (length: number) => {
    return CryptoLib.randomBytes(length).then((bytes: string) => {
      return Buffer.from(bytes, 'base64');
    });
  },
};

export default CryptoLibJs as CryptoLibType;
