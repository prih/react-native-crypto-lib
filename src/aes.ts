import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

export enum PADDING_MODE {
  ZERO = 0,
  PKCS7 = 1,
}

const { CryptoLib: CryptoLibNative } = NativeModules;

export async function encrypt(
  key: Buffer,
  iv: Buffer,
  data: Buffer,
  mode: PADDING_MODE = PADDING_MODE.PKCS7
): Promise<Buffer> {
  const result = await CryptoLibNative.encrypt(
    key.toString('base64'),
    iv.toString('base64'),
    data.toString('base64'),
    mode
  );

  return Buffer.from(result, 'base64');
}

export async function decrypt(
  key: Buffer,
  iv: Buffer,
  data: Buffer,
  mode: PADDING_MODE = PADDING_MODE.PKCS7
): Promise<Buffer> {
  const result = await CryptoLibNative.decrypt(
    key.toString('base64'),
    iv.toString('base64'),
    data.toString('base64'),
    mode
  );

  return Buffer.from(result, 'base64');
}
