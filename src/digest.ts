import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

const HASH_TYPE = {
  sha1: 0,
  sha256: 1,
  sha512: 2,
  sha3_256: 3,
  sha3_512: 4,
  keccak256: 5,
  keccak512: 6,
  ripemd160: 7,
  rmd160: 7,
  hash256: 8,
  hash160: 9,
} as {
  [key: string]: number;
};

const { CryptoLib: CryptoLibNative } = NativeModules;

export const createHash = (type: string, data: Buffer): Buffer => {
  return Buffer.from(
    CryptoLibNative.hash(HASH_TYPE[type], data.toString('base64')),
    'base64'
  );
};

export const createHmac = (type: string, key: Buffer, data: Buffer): Buffer => {
  return Buffer.from(
    CryptoLibNative.hmac(
      HASH_TYPE[type],
      key.toString('base64'),
      data.toString('base64')
    ),
    'base64'
  );
};

export const pbkdf2 = (
  pass: String | Buffer,
  salt: String | Buffer,
  iterations = 10000,
  keyLength = 32,
  digest = 'sha256'
): Promise<Buffer> => {
  return CryptoLibNative.pbkdf2(
    HASH_TYPE[digest],
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
  digest = 'sha256'
): Buffer => {
  return Buffer.from(
    CryptoLibNative.pbkdf2Sync(
      HASH_TYPE[digest],
      Buffer.from(pass).toString('base64'),
      Buffer.from(salt).toString('base64'),
      iterations,
      keyLength
    ),
    'base64'
  );
};
