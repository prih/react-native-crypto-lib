import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

const CryptoLib = NativeModules.CryptoLib;

export const randomNumber: () => Promise<number> = CryptoLib.randomNumber;

export const randomBytes = async (length: number): Promise<Buffer> => {
  return Buffer.from(await CryptoLib.randomBytes(length), 'base64');
};
