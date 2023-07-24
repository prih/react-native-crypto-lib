import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
const CryptoLib = NativeModules.CryptoLib;
export const randomNumber = CryptoLib.randomNumber;
export const randomBytes = async length => {
  return Buffer.from(await CryptoLib.randomBytes(length), 'base64');
};
//# sourceMappingURL=rng.js.map