import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
import * as ecdsa from './ecdsa';
import * as schnorr from './schnorr';
const {
  CryptoLib: CryptoLibNative
} = NativeModules;
export default {
  isPoint: pub => {
    if (pub.length === 33 || pub.length === 65) {
      return ecdsa.ecdsaValidatePublic(pub);
    }
    if (pub.length === 32) {
      return schnorr.verifyPublic(pub);
    }
    return false;
  },
  isXOnlyPoint: pub => {
    if (pub.length === 32) {
      return schnorr.verifyPublic(pub);
    }
    return false;
  },
  xOnlyPointAddTweak: (pub, tweak) => {
    if (pub.length !== 32 || tweak.length !== 32) {
      return null;
    }
    const res = CryptoLibNative.xOnlyPointAddTweak(pub.toString('base64'), tweak.toString('base64'));
    if (!res) {
      return null;
    }
    return {
      parity: res.parity,
      xOnlyPubkey: Buffer.from(res.xOnlyPubkey, 'base64')
    };
  }
};
//# sourceMappingURL=ecc.js.map