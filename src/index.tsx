import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

export enum HMAC {
  SHA256 = 0,
  SHA512 = 1,
}

export enum HASH {
  SHA1 = 0,
  SHA256 = 1,
  SHA512 = 2,
  SHA3_256 = 3,
  SHA3_512 = 4,
  KECCAK_256 = 5,
  KECCAK_512 = 6,
  RIPEMD160 = 7,
}

type CryptoLibType = {
  randomNumber(): number;
  randomBytes(length: number): Buffer;
  hash(type: HASH, data: Buffer): Buffer;
  hmac(type: HMAC, key: Buffer, data: Buffer): Buffer;
};

const { CryptoLib } = NativeModules;

const CryptoLibJs = {
  randomNumber: CryptoLib.randomNumber,
  randomBytes: (length: number) => {
    return Buffer.from(CryptoLib.randomBytes(length), 'base64');
  },
  hash: (type: HASH, data: Buffer) => {
    return Buffer.from(CryptoLib.hash(type, data.toString('base64')), 'base64');
  },
  hmac: (type: HMAC, key: Buffer, data: Buffer) => {
    return Buffer.from(
      CryptoLib.hmac(type, key.toString('base64'), data.toString('base64')),
      'base64'
    );
  },
};

export default CryptoLibJs as CryptoLibType;
