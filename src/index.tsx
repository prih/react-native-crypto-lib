import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

import * as rand from './rand';
import * as bip32 from './bip32';
import * as digest from './digest';
import * as secp256k1 from './secp256k1';

export { rand, bip32, digest, secp256k1 };

type bip39Type = {
  mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Buffer>;
  mnemonicToSeedSync(mnemonic: string, passphrase?: string): Buffer;
  generateMnemonic(strength?: number): String;
  validateMnemonic(mnemonic: string): Boolean;
};

const { CryptoLib: CryptoLibNative } = NativeModules;

export const bip39 = {
  mnemonicToSeed: (mnemonic: string, passphrase: string = '') => {
    return CryptoLibNative.mnemonicToSeed(mnemonic, passphrase).then(
      (result: string) => {
        return Buffer.from(result, 'base64');
      }
    );
  },
  mnemonicToSeedSync: (mnemonic: string, passphrase: string = '') => {
    return Buffer.from(
      CryptoLibNative.mnemonicToSeedSync(mnemonic, passphrase),
      'base64'
    );
  },
  generateMnemonic: (strength: number = 12) => {
    return CryptoLibNative.generateMnemonic(strength);
  },
  validateMnemonic: (mnemonic: string) => {
    return CryptoLibNative.validateMnemonic(mnemonic) === 1;
  },
} as bip39Type;
