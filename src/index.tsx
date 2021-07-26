import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

import * as rand from './rand';
import * as bip32 from './bip32';
import * as digest from './digest';

export { rand, bip32, digest };

type bip39Type = {
  mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Buffer>;
  mnemonicToSeedSync(mnemonic: string, passphrase?: string): Buffer;
  generateMnemonic(strength?: number): String;
  validateMnemonic(mnemonic: string): Boolean;
};

type signType = {
  signature: Buffer;
  recid: number;
};

type secp256k1Type = {
  randomPrivate(): Buffer;
  readPublic(pub: Buffer, compact?: Boolean): Buffer;
  validatePublic(pub: Buffer): Boolean;
  validatePrivate(priv: Buffer): Boolean;
  getPublic(priv: Buffer, compact?: Boolean): Buffer;
  recover(
    sig: Buffer,
    digest: Buffer,
    recid: number,
    compact?: Boolean
  ): Buffer;
  ecdh(
    pub: Buffer,
    priv: Buffer,
    compact?: Boolean,
    hashfn?: string | undefined
  ): Buffer;
  verify(pub: Buffer, sig: Buffer, digest: Buffer): Boolean;
  sign(priv: Buffer, digest: Buffer): Promise<signType>;
  signSync(priv: Buffer, digest: Buffer): signType;
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

export const secp256k1 = {
  randomPrivate: () => {
    const result = CryptoLibNative.ecdsaRandomPrivate();

    if (!result) {
      throw new Error('wrong key');
    }

    return Buffer.from(result, 'base64');
  },
  readPublic: (pub: Buffer, compact: Boolean = true) => {
    const result = CryptoLibNative.ecdsaReadPublic(
      pub.toString('base64'),
      compact ? 1 : 0
    );

    if (!result) {
      throw new Error('wrong key');
    }

    return Buffer.from(result, 'base64');
  },
  validatePublic: (pub: Buffer) => {
    return CryptoLibNative.ecdsaValidatePublic(pub.toString('base64')) === 1;
  },
  validatePrivate: (priv: Buffer) => {
    const result = CryptoLibNative.ecdsaValidatePrivate(
      priv.toString('base64')
    );
    return result === 1;
  },
  getPublic: (priv: Buffer, compact: Boolean = true) => {
    let result = null;
    if (compact) {
      result = CryptoLibNative.ecdsaGetPublic33(priv.toString('base64'));
    } else {
      result = CryptoLibNative.ecdsaGetPublic65(priv.toString('base64'));
    }

    if (!result) {
      throw new Error('wrong key');
    }

    return Buffer.from(result, 'base64');
  },
  recover: (
    sig: Buffer,
    msg: Buffer,
    recid: number,
    compact: Boolean = true
  ) => {
    const result = CryptoLibNative.ecdsaRecover(
      sig.toString('base64'),
      msg.toString('base64'),
      recid,
      compact ? 1 : 0
    );

    if (!result) {
      throw new Error('recover error');
    }

    return Buffer.from(result, 'base64');
  },
  ecdh: (
    pub: Buffer,
    priv: Buffer,
    compact: Boolean = true,
    hashfn = 'sha256'
  ) => {
    const result = CryptoLibNative.ecdsaEcdh(
      pub.toString('base64'),
      priv.toString('base64'),
      compact ? 1 : 0
    );

    if (!result) {
      throw new Error('recover error');
    }

    if (hashfn === undefined) {
      return Buffer.from(result, 'base64');
    }

    return digest.createHash(hashfn, result);
  },
  verify: (pub: Buffer, sig: Buffer, msg: Buffer) => {
    const result = CryptoLibNative.ecdsaVerify(
      pub.toString('base64'),
      sig.toString('base64'),
      msg.toString('base64')
    );
    return result === 1;
  },
  sign: (priv: Buffer, msg: Buffer) => {
    return CryptoLibNative.ecdsaSign(
      priv.toString('base64'),
      msg.toString('base64')
    ).then((result: string) => {
      const sig = Buffer.from(result, 'base64');
      return {
        signature: sig.slice(1),
        recid: Number(sig[0]),
      } as signType;
    });
  },
  signSync: (priv: Buffer, msg: Buffer) => {
    const result = CryptoLibNative.ecdsaSignSync(
      priv.toString('base64'),
      msg.toString('base64')
    );

    if (!result) {
      throw new Error('recover error');
    }

    const sig = Buffer.from(result, 'base64');
    return {
      signature: sig.slice(1),
      recid: Number(sig[0]),
    } as signType;
  },
} as secp256k1Type;
