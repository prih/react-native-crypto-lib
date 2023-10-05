import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
const {
  CryptoLib: CryptoLibNative
} = NativeModules;
export function getPublic(priv) {
  return Buffer.from(CryptoLibNative.schnorrGetPublic(priv.toString('base64')), 'base64');
}
export function sign(priv, digest) {
  return Buffer.from(CryptoLibNative.schnorrSign(priv.toString('base64'), digest.toString('base64')), 'base64');
}
export async function signAsync(priv, digest) {
  return Buffer.from(await CryptoLibNative.schnorrSignAsync(priv.toString('base64'), digest.toString('base64')), 'base64');
}
export function verify(pub, sig, digest) {
  const valid = CryptoLibNative.schnorrVerify(pub.toString('base64'), sig.toString('base64'), digest.toString('base64'));
  return valid === 1;
}
//# sourceMappingURL=schnorr.js.map