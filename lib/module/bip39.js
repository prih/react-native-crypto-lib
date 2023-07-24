import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
const {
  CryptoLib: CryptoLibNative
} = NativeModules;
export const mnemonicToSeed = function (mnemonic) {
  let passphrase = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
  return CryptoLibNative.mnemonicToSeed(mnemonic, passphrase).then(result => {
    return Buffer.from(result, 'base64');
  });
};
export const generateMnemonic = function () {
  let strength = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 128;
  if (strength % 32 || strength < 128 || strength > 256) {
    throw new Error('strength % 32 || strength < 128 || strength > 256');
  }
  return CryptoLibNative.generateMnemonic(strength);
};
export const validateMnemonic = mnemonic => {
  return CryptoLibNative.validateMnemonic(mnemonic).then(valid => {
    return valid === 1;
  });
};
//# sourceMappingURL=bip39.js.map