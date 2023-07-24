"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.pbkdf2 = exports.createHmac = exports.createHash = exports.PBKDF2_HASH = exports.HMAC_HASH = exports.HASH = void 0;
var _reactNative = require("react-native");
var _buffer = require("buffer");
let HASH = /*#__PURE__*/function (HASH) {
  HASH[HASH["SHA1"] = 0] = "SHA1";
  HASH[HASH["SHA256"] = 1] = "SHA256";
  HASH[HASH["SHA512"] = 2] = "SHA512";
  HASH[HASH["SHA3_256"] = 3] = "SHA3_256";
  HASH[HASH["SHA3_512"] = 4] = "SHA3_512";
  HASH[HASH["KECCAK256"] = 5] = "KECCAK256";
  HASH[HASH["KECCAK512"] = 6] = "KECCAK512";
  HASH[HASH["RIPEMD160"] = 7] = "RIPEMD160";
  HASH[HASH["HASH256"] = 8] = "HASH256";
  HASH[HASH["HASH160"] = 9] = "HASH160";
  return HASH;
}({});
exports.HASH = HASH;
let HMAC_HASH = /*#__PURE__*/function (HMAC_HASH) {
  HMAC_HASH[HMAC_HASH["SHA256"] = 1] = "SHA256";
  HMAC_HASH[HMAC_HASH["SHA512"] = 2] = "SHA512";
  return HMAC_HASH;
}({});
exports.HMAC_HASH = HMAC_HASH;
let PBKDF2_HASH = /*#__PURE__*/function (PBKDF2_HASH) {
  PBKDF2_HASH[PBKDF2_HASH["SHA256"] = 1] = "SHA256";
  PBKDF2_HASH[PBKDF2_HASH["SHA512"] = 2] = "SHA512";
  return PBKDF2_HASH;
}({});
exports.PBKDF2_HASH = PBKDF2_HASH;
const {
  CryptoLib: CryptoLibNative
} = _reactNative.NativeModules;
const createHash = (type, data) => {
  return _buffer.Buffer.from(CryptoLibNative.hash(type, data.toString('base64')), 'base64');
};
exports.createHash = createHash;
const createHmac = (type, key, data) => {
  return _buffer.Buffer.from(CryptoLibNative.hmac(type, key.toString('base64'), data.toString('base64')), 'base64');
};
exports.createHmac = createHmac;
const pbkdf2 = function (pass, salt) {
  let iterations = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 10000;
  let keyLength = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 32;
  let digest = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : PBKDF2_HASH.SHA256;
  return CryptoLibNative.pbkdf2(digest, _buffer.Buffer.from(pass).toString('base64'), _buffer.Buffer.from(salt).toString('base64'), iterations, keyLength).then(hash => {
    return _buffer.Buffer.from(hash, 'base64');
  });
};
exports.pbkdf2 = pbkdf2;
//# sourceMappingURL=digest.js.map