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
  randomNumber(): Promise<number>;
  randomBytes(length: number): Promise<Buffer>;
  hash(type: HASH, data: Buffer): Promise<Buffer>;
  hmac(type: HMAC, key: Buffer, data: Buffer): Promise<Buffer>;
};

const { CryptoLib } = NativeModules;

const CryptoLibJs = {
  randomNumber: CryptoLib.randomNumber,
  randomBytes: (length: number) => {
    return CryptoLib.randomBytes(length).then((bytes: string) => {
      return Buffer.from(bytes, 'base64');
    });
  },
  hash: (type: HASH, data: Buffer) => {
    return CryptoLib.hash(type, data.toString('base64')).then(
      (hash: string) => {
        return Buffer.from(hash, 'base64');
      }
    );
  },
  hmac: (type: HMAC, key: Buffer, data: Buffer) => {
    return CryptoLib.hmac(
      type,
      key.toString('base64'),
      data.toString('base64')
    ).then((hash: string) => {
      return Buffer.from(hash, 'base64');
    });
  },
};

export default CryptoLibJs as CryptoLibType;
