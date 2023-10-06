"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getPublic = getPublic;
exports.sign = sign;
exports.signAsync = signAsync;
exports.tweakPrivateKey = tweakPrivateKey;
exports.tweakPublicKey = tweakPublicKey;
exports.verify = verify;
exports.verifyPublic = verifyPublic;
var _reactNative = require("react-native");
var _buffer = require("buffer");
const {
  CryptoLib: CryptoLibNative
} = _reactNative.NativeModules;
function getPublic(priv) {
  return _buffer.Buffer.from(CryptoLibNative.schnorrGetPublic(priv.toString('base64')), 'base64');
}
function sign(priv, digest) {
  return _buffer.Buffer.from(CryptoLibNative.schnorrSign(priv.toString('base64'), digest.toString('base64')), 'base64');
}
async function signAsync(priv, digest) {
  return _buffer.Buffer.from(await CryptoLibNative.schnorrSignAsync(priv.toString('base64'), digest.toString('base64')), 'base64');
}
function verify(pub, sig, digest) {
  const valid = CryptoLibNative.schnorrVerify(pub.toString('base64'), sig.toString('base64'), digest.toString('base64'));
  return valid === 1;
}
function tweakPublicKey(pub, root) {
  return _buffer.Buffer.from(CryptoLibNative.schnorrTweakPublic(pub.toString('base64'), root ? root.toString('base64') : ''), 'base64');
}
function tweakPrivateKey(priv, root) {
  return _buffer.Buffer.from(CryptoLibNative.schnorrTweakPrivate(priv.toString('base64'), root ? root.toString('base64') : ''), 'base64');
}
function verifyPublic(pub) {
  if (pub.length !== 32) {
    return false;
  }
  const valid = CryptoLibNative.schnorrVerifyPub(pub.toString('base64'));
  return valid === 1;
}
//# sourceMappingURL=schnorr.js.map