import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
import { createHash, HASH } from './digest';
const {
  CryptoLib: CryptoLibNative
} = NativeModules;
export const ecdsaRandomPrivate = async () => {
  return Buffer.from(await CryptoLibNative.ecdsaRandomPrivate(), 'base64');
};
export const ecdsaValidatePrivate = pk => {
  const valid = CryptoLibNative.ecdsaValidatePrivate(pk.toString('base64'));
  return valid === 1;
};
export const ecdsaGetPublic = function (pk) {
  let compact = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
  return Buffer.from(CryptoLibNative.ecdsaGetPublic(pk.toString('base64'), compact), 'base64');
};
export const ecdsaReadPublic = function (pub) {
  let compact = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
  return Buffer.from(CryptoLibNative.ecdsaReadPublic(pub.toString('base64'), compact), 'base64');
};
export const ecdsaValidatePublic = pub => {
  const valid = CryptoLibNative.ecdsaValidatePublic(pub.toString('base64'));
  return valid === 1;
};
export const ecdsaRecover = (sign, recId, digest) => {
  return Buffer.from(CryptoLibNative.ecdsaRecover(sign.toString('base64'), recId, digest.toString('base64')), 'base64');
};
export const ecdsaEcdh = function (pub, priv) {
  let compact = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;
  let hash = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : HASH.SHA256;
  const ecdh = Buffer.from(CryptoLibNative.ecdsaEcdh(pub.toString('base64'), priv.toString('base64'), compact), 'base64');
  return createHash(hash, ecdh);
};
export const ecdsaVerify = (pub, sign, digest) => {
  const valid = CryptoLibNative.ecdsaVerify(pub.toString('base64'), sign.toString('base64'), digest.toString('base64'));
  return valid === 1;
};
export const ecdsaSign = (priv, digest) => {
  const res = Buffer.from(CryptoLibNative.ecdsaSign(priv.toString('base64'), digest.toString('base64')), 'base64');
  return {
    signature: res.slice(1),
    recId: Number(res[0])
  };
};
//# sourceMappingURL=ecdsa.js.map