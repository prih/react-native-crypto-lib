import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

const { CryptoLib: CryptoLibNative } = NativeModules;

export const mnemonicToSeed = (
  mnemonic: string,
  passphrase: string = ''
): Promise<Buffer> => {
  return CryptoLibNative.mnemonicToSeed(mnemonic, passphrase).then(
    (result: string) => {
      return Buffer.from(result, 'base64');
    }
  );
};

export const generateMnemonic = (strength: number = 128): Promise<string> => {
  if (strength % 32 || strength < 128 || strength > 256) {
    throw new Error('strength % 32 || strength < 128 || strength > 256');
  }
  return CryptoLibNative.generateMnemonic(strength);
};

export const validateMnemonic = (mnemonic: string): Promise<boolean> => {
  return CryptoLibNative.validateMnemonic(mnemonic).then((valid: number) => {
    return valid === 1;
  });
};
