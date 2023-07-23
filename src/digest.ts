import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

export enum HASH {
  SHA1 = 0,
  SHA256 = 1,
  SHA512 = 2,
  SHA3_256 = 3,
  SHA3_512 = 4,
  KECCAK256 = 5,
  KECCAK512 = 6,
  RIPEMD160 = 7,
  HASH256 = 8,
  HASH160 = 9,
}

export enum HMAC_HASH {
  SHA256 = 1,
  SHA512 = 2,
}

export enum PBKDF2_HASH {
  SHA256 = 1,
  SHA512 = 2,
}

const { CryptoLib: CryptoLibNative } = NativeModules;

export const createHash = (type: HASH, data: Buffer): Buffer => {
  return Buffer.from(
    CryptoLibNative.hash(type, data.toString('base64')),
    'base64'
  );
};

export const createHmac = (
  type: HMAC_HASH,
  key: Buffer,
  data: Buffer
): Buffer => {
  return Buffer.from(
    CryptoLibNative.hmac(type, key.toString('base64'), data.toString('base64')),
    'base64'
  );
};

export const pbkdf2 = (
  pass: string | Buffer,
  salt: string | Buffer,
  iterations = 10000,
  keyLength = 32,
  digest = PBKDF2_HASH.SHA256
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
