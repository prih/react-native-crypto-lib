"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.validateMnemonic = exports.mnemonicToSeed = exports.generateMnemonic = void 0;
var _reactNative = require("react-native");
var _buffer = require("buffer");
const {
  CryptoLib: CryptoLibNative
} = _reactNative.NativeModules;
const mnemonicToSeed = function (mnemonic) {
  let passphrase = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
  return CryptoLibNative.mnemonicToSeed(mnemonic, passphrase).then(result => {
    return _buffer.Buffer.from(result, 'base64');
  });
};
exports.mnemonicToSeed = mnemonicToSeed;
const generateMnemonic = function () {
  let strength = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 128;
  if (strength % 32 || strength < 128 || strength > 256) {
    throw new Error('strength % 32 || strength < 128 || strength > 256');
  }
  return CryptoLibNative.generateMnemonic(strength);
};
exports.generateMnemonic = generateMnemonic;
const validateMnemonic = mnemonic => {
  return CryptoLibNative.validateMnemonic(mnemonic).then(valid => {
    return valid === 1;
  });
};
exports.validateMnemonic = validateMnemonic;
//# sourceMappingURL=bip39.js.map