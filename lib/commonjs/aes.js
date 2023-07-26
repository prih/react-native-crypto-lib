"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.PADDING_MODE = void 0;
exports.decrypt = decrypt;
exports.encrypt = encrypt;
var _reactNative = require("react-native");
var _buffer = require("buffer");
let PADDING_MODE = /*#__PURE__*/function (PADDING_MODE) {
  PADDING_MODE[PADDING_MODE["ZERO"] = 0] = "ZERO";
  PADDING_MODE[PADDING_MODE["PKCS7"] = 1] = "PKCS7";
  return PADDING_MODE;
}({});
exports.PADDING_MODE = PADDING_MODE;
const {
  CryptoLib: CryptoLibNative
} = _reactNative.NativeModules;
async function encrypt(key, iv, data) {
  let mode = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : PADDING_MODE.PKCS7;
  const result = await CryptoLibNative.encrypt(key.toString('base64'), iv.toString('base64'), data.toString('base64'), mode);
  return _buffer.Buffer.from(result, 'base64');
}
async function decrypt(key, iv, data) {
  let mode = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : PADDING_MODE.PKCS7;
  const result = await CryptoLibNative.decrypt(key.toString('base64'), iv.toString('base64'), data.toString('base64'), mode);
  return _buffer.Buffer.from(result, 'base64');
}
//# sourceMappingURL=aes.js.map