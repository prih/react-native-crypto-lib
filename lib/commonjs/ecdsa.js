"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ecdsaVerify = exports.ecdsaValidatePublic = exports.ecdsaValidatePrivate = exports.ecdsaSign = exports.ecdsaRecover = exports.ecdsaReadPublic = exports.ecdsaRandomPrivate = exports.ecdsaGetPublic = exports.ecdsaEcdh = void 0;
var _reactNative = require("react-native");
var _buffer = require("buffer");
var _digest = require("./digest");
const {
  CryptoLib: CryptoLibNative
} = _reactNative.NativeModules;
const ecdsaRandomPrivate = async () => {
  return _buffer.Buffer.from(await CryptoLibNative.ecdsaRandomPrivate(), 'base64');
};
exports.ecdsaRandomPrivate = ecdsaRandomPrivate;
const ecdsaValidatePrivate = pk => {
  const valid = CryptoLibNative.ecdsaValidatePrivate(pk.toString('base64'));
  return valid === 1;
};
exports.ecdsaValidatePrivate = ecdsaValidatePrivate;
const ecdsaGetPublic = function (pk) {
  let compact = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
  return _buffer.Buffer.from(CryptoLibNative.ecdsaGetPublic(pk.toString('base64'), compact), 'base64');
};
exports.ecdsaGetPublic = ecdsaGetPublic;
const ecdsaReadPublic = function (pub) {
  let compact = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
  return _buffer.Buffer.from(CryptoLibNative.ecdsaReadPublic(pub.toString('base64'), compact), 'base64');
};
exports.ecdsaReadPublic = ecdsaReadPublic;
const ecdsaValidatePublic = pub => {
  const valid = CryptoLibNative.ecdsaValidatePublic(pub.toString('base64'));
  return valid === 1;
};
exports.ecdsaValidatePublic = ecdsaValidatePublic;
const ecdsaRecover = (sign, recId, digest) => {
  return _buffer.Buffer.from(CryptoLibNative.ecdsaRecover(sign.toString('base64'), recId, digest.toString('base64')), 'base64');
};
exports.ecdsaRecover = ecdsaRecover;
const ecdsaEcdh = function (pub, priv) {
  let compact = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;
  let hash = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : _digest.HASH.SHA256;
  const ecdh = _buffer.Buffer.from(CryptoLibNative.ecdsaEcdh(pub.toString('base64'), priv.toString('base64'), compact), 'base64');
  return (0, _digest.createHash)(hash, ecdh);
};
exports.ecdsaEcdh = ecdsaEcdh;
const ecdsaVerify = (pub, sign, digest) => {
  const valid = CryptoLibNative.ecdsaVerify(pub.toString('base64'), sign.toString('base64'), digest.toString('base64'));
  return valid === 1;
};
exports.ecdsaVerify = ecdsaVerify;
const ecdsaSign = (priv, digest) => {
  const res = _buffer.Buffer.from(CryptoLibNative.ecdsaSign(priv.toString('base64'), digest.toString('base64')), 'base64');
  return {
    signature: res.slice(1),
    recId: Number(res[0])
  };
};
exports.ecdsaSign = ecdsaSign;
//# sourceMappingURL=ecdsa.js.map