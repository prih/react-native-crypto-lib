import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

import * as ecdsa from './ecdsa';
import * as schnorr from './schnorr';

const { CryptoLib: CryptoLibNative } = NativeModules;

export interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

export interface TinySecp256k1Interface {
  isPoint(p: Uint8Array): boolean;
  isXOnlyPoint(p: Uint8Array): boolean;
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array
  ): XOnlyPointAddTweakResult | null;
}

export default {
  isPoint: (pub: Buffer): boolean => {
    if (pub.length === 33 || pub.length === 65) {
      return ecdsa.ecdsaValidatePublic(pub);
    }

    if (pub.length === 32) {
      return schnorr.verifyPublic(pub);
    }

    return false;
  },
  isXOnlyPoint: (pub: Buffer): boolean => {
    if (pub.length === 32) {
      return schnorr.verifyPublic(pub);
    }

    return false;
  },
  xOnlyPointAddTweak: (
    pub: Buffer,
    tweak: Buffer
  ): XOnlyPointAddTweakResult | null => {
    if (pub.length !== 32 || tweak.length !== 32) {
      return null;
    }

    const res = CryptoLibNative.xOnlyPointAddTweak(
      pub.toString('base64'),
      tweak.toString('base64')
    );

    if (!res) {
      return null;
    }

    return {
      parity: res.parity,
      xOnlyPubkey: Buffer.from(res.xOnlyPubkey, 'base64'),
    } as XOnlyPointAddTweakResult;
  },
} as TinySecp256k1Interface;
