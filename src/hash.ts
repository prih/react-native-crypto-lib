import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

export enum HASH_TYPE {
  SHA1 = 0,
  SHA256 = 1,
  SHA512 = 2,
  SHA3_256 = 3,
  SHA3_512 = 4,
  KECCAK_256 = 5,
  KECCAK_512 = 6,
  RIPEMD160 = 7,
}

export enum HMAC_TYPE {
  SHA256 = 0,
  SHA512 = 1,
}

const { CryptoLib: CryptoLibNative } = NativeModules;

export const createHash = (type: HASH_TYPE, data: Buffer): Buffer => {
  return Buffer.from(
    CryptoLibNative.hash(type, data.toString('base64')),
    'base64'
  );
};

export const createHmac = (
  type: HMAC_TYPE,
  key: Buffer,
  data: Buffer
): Buffer => {
  return Buffer.from(
    CryptoLibNative.hmac(type, key.toString('base64'), data.toString('base64')),
    'base64'
  );
};

export const pbkdf2 = (
  pass: String | Buffer,
  salt: String | Buffer,
  iterations = 10000,
  keyLength = 32,
  digest = HMAC_TYPE.SHA256
): Promise<Buffer> => {
  return CryptoLibNative.pbkdf2(
    digest,
    Buffer.from(pass).toString('base64'),
    Buffer.from(salt).toString('base64'),
    iterations,
    keyLength
  ).then((hash: string) => {
    return Buffer.from(hash, 'base64');
  });
};

export const pbkdf2Sync = (
  pass: String | Buffer,
  salt: String | Buffer,
  iterations = 10000,
  keyLength = 32,
  digest = HMAC_TYPE.SHA256
): Buffer => {
  return Buffer.from(
    CryptoLibNative.pbkdf2Sync(
      digest,
      Buffer.from(pass).toString('base64'),
      Buffer.from(salt).toString('base64'),
      iterations,
      keyLength
    ),
    'base64'
  );
};
