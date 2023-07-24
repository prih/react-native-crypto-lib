"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.randomNumber = exports.randomBytes = void 0;
var _reactNative = require("react-native");
var _buffer = require("buffer");
const CryptoLib = _reactNative.NativeModules.CryptoLib;
const randomNumber = CryptoLib.randomNumber;
exports.randomNumber = randomNumber;
const randomBytes = async length => {
  return _buffer.Buffer.from(await CryptoLib.randomBytes(length), 'base64');
};
exports.randomBytes = randomBytes;
//# sourceMappingURL=rng.js.map