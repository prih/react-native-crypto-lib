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
  randomBytes(length: number): Promise<Buffer>;
  randomBytesSync(length: number): Buffer;
  hash(type: HASH, data: Buffer): Buffer;
  hmac(type: HMAC, key: Buffer, data: Buffer): Buffer;
  pbkdf2(
    pass: String | Buffer,
    salt: String | Buffer,
    iterations?: number,
    keyLength?: number,
    digest?: HMAC
  ): Promise<Buffer>;
  pbkdf2Sync(
    pass: String | Buffer,
    salt: String | Buffer,
    iterations?: number,
    keyLength?: number,
    digest?: HMAC
  ): Buffer;
  mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Buffer>;
  mnemonicToSeedSync(mnemonic: string, passphrase?: string): Buffer;
  generateMnemonic(strength?: number): String;
  validateMnemonic(mnemonic: string): Boolean;
  ecdsaRandomPrivate(): Buffer;
  ecdsaValidatePublic(pub: Buffer): Boolean;
  ecdsaValidatePrivate(priv: Buffer): Boolean;
  ecdsaGetPublic(priv: Buffer, compress?: Boolean): Buffer;
  ecdsaRecover(
    sig: Buffer,
    digest: Buffer,
    recid: number,
    compress?: Boolean
  ): Buffer;
};

const { CryptoLib } = NativeModules;

const CryptoLibJs = {
  randomNumber: CryptoLib.randomNumber,
  randomBytes: (length: number) => {
    return CryptoLib.randomBytes(length).then((bytes: string) => {
      return Buffer.from(bytes, 'base64');
    });
  },
  randomBytesSync: (length: number) => {
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
  pbkdf2: (
    pass: String | Buffer,
    salt: String | Buffer,
    iterations = 10000,
    keyLength = 32,
    digest = HMAC.SHA256
  ) => {
    return CryptoLib.pbkdf2(
      digest,
      Buffer.from(pass).toString('base64'),
      Buffer.from(salt).toString('base64'),
      iterations,
      keyLength
    ).then((hash: string) => {
      return Buffer.from(hash, 'base64');
    });
  },
  pbkdf2Sync: (
    pass: String | Buffer,
    salt: String | Buffer,
    iterations = 10000,
    keyLength = 32,
    digest = HMAC.SHA256
  ) => {
    return Buffer.from(
      CryptoLib.pbkdf2Sync(
        digest,
        Buffer.from(pass).toString('base64'),
        Buffer.from(salt).toString('base64'),
        iterations,
        keyLength
      ),
      'base64'
    );
  },
  mnemonicToSeed: (mnemonic: string, passphrase: string = '') => {
    return CryptoLib.mnemonicToSeed(mnemonic, passphrase).then(
      (result: string) => {
        return Buffer.from(result, 'base64');
      }
    );
  },
  mnemonicToSeedSync: (mnemonic: string, passphrase: string = '') => {
    return Buffer.from(
      CryptoLib.mnemonicToSeedSync(mnemonic, passphrase),
      'base64'
    );
  },
  generateMnemonic: (strength: number = 12) => {
    return CryptoLib.generateMnemonic(strength);
  },
  validateMnemonic: (mnemonic: string) => {
    return CryptoLib.validateMnemonic(mnemonic) === 1;
  },
  ecdsaRandomPrivate: () => {
    const result = CryptoLib.ecdsaRandomPrivate();

    if (!result) {
      throw new Error('wrong key');
    }

    return Buffer.from(result, 'base64');
  },
  ecdsaValidatePublic: (pub: Buffer) => {
    return CryptoLib.ecdsaValidatePublic(pub.toString('base64')) === 1;
  },
  ecdsaValidatePrivate: (priv: Buffer) => {
    const result = CryptoLib.ecdsaValidatePrivate(priv.toString('base64'));
    return result === 1;
  },
  ecdsaGetPublic: (priv: Buffer, compress: Boolean = true) => {
    let result = null;
    if (compress) {
      result = CryptoLib.ecdsaGetPublic33(priv.toString('base64'));
    } else {
      result = CryptoLib.ecdsaGetPublic65(priv.toString('base64'));
    }

    if (!result) {
      throw new Error('wrong key');
    }

    return Buffer.from(result, 'base64');
  },
  ecdsaRecover: (
    sig: Buffer,
    digest: Buffer,
    recid: number,
    compress: Boolean = true
  ) => {
    const result = CryptoLib.ecdsaRecover(
      sig.toString('base64'),
      digest.toString('base64'),
      recid,
      compress ? 1 : 0
    );

    if (!result) {
      throw new Error('recover error');
    }

    return Buffer.from(result, 'base64');
  },
};

export default CryptoLibJs as CryptoLibType;
