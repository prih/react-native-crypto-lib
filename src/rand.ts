import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

const { CryptoLib: CryptoLibNative } = NativeModules;

export const randomNumber = CryptoLibNative.randomNumber;

export const randomBytes = (length: number) => {
  return CryptoLibNative.randomBytes(length).then((bytes: string) => {
    return Buffer.from(bytes, 'base64');
  });
};

export const randomBytesSync = (length: number) => {
  return Buffer.from(CryptoLibNative.randomBytes(length), 'base64');
};
