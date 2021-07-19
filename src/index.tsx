import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

type CryptoLibType = {
  randomNumber(): Promise<number>;
  randomBytes(length: number): Promise<Buffer>;
  sha1(data: Buffer): Promise<Buffer>;
  sha256(data: Buffer): Promise<Buffer>;
  sha512(data: Buffer): Promise<Buffer>;
};

const { CryptoLib } = NativeModules;

const CryptoLibJs = {
  randomNumber: CryptoLib.randomNumber,
  randomBytes: (length: number) => {
    return CryptoLib.randomBytes(length).then((bytes: string) => {
      return Buffer.from(bytes, 'base64');
    });
  },
  sha1: (data: Buffer) => {
    return CryptoLib.sha1(data.toString('base64')).then((hash: string) => {
      return Buffer.from(hash, 'base64');
    });
  },
  sha256: (data: Buffer) => {
    return CryptoLib.sha256(data.toString('base64')).then((hash: string) => {
      return Buffer.from(hash, 'base64');
    });
  },
  sha512: (data: Buffer) => {
    return CryptoLib.sha512(data.toString('base64')).then((hash: string) => {
      return Buffer.from(hash, 'base64');
    });
  },
};

export default CryptoLibJs as CryptoLibType;
