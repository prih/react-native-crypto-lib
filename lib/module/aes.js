import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
export let PADDING_MODE = /*#__PURE__*/function (PADDING_MODE) {
  PADDING_MODE[PADDING_MODE["ZERO"] = 0] = "ZERO";
  PADDING_MODE[PADDING_MODE["PKCS7"] = 1] = "PKCS7";
  return PADDING_MODE;
}({});
const {
  CryptoLib: CryptoLibNative
} = NativeModules;
export async function encrypt(key, iv, data) {
  let mode = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : PADDING_MODE.PKCS7;
  const result = await CryptoLibNative.encrypt(key.toString('base64'), iv.toString('base64'), data.toString('base64'), mode);
  return Buffer.from(result, 'base64');
}
export async function decrypt(key, iv, data) {
  let mode = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : PADDING_MODE.PKCS7;
  const result = await CryptoLibNative.decrypt(key.toString('base64'), iv.toString('base64'), data.toString('base64'), mode);
  return Buffer.from(result, 'base64');
}
//# sourceMappingURL=aes.js.map