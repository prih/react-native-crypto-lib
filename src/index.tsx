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
};

type bip39Type = {
  mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Buffer>;
  mnemonicToSeedSync(mnemonic: string, passphrase?: string): Buffer;
  generateMnemonic(strength?: number): String;
  validateMnemonic(mnemonic: string): Boolean;
};

type secp256k1Type = {
  randomPrivate(): Buffer;
  validatePublic(pub: Buffer): Boolean;
  validatePrivate(priv: Buffer): Boolean;
  getPublic(priv: Buffer, compact?: Boolean): Buffer;
  recover(
    sig: Buffer,
    digest: Buffer,
    recid: number,
    compact?: Boolean
  ): Buffer;
  ecdh(
    pub: Buffer,
    priv: Buffer,
    compact?: Boolean,
    hashfn?: HASH | undefined
  ): Buffer;
  verify(pub: Buffer, sig: Buffer, digest: Buffer): Boolean;
  sign(priv: Buffer, digest: Buffer): Promise<Buffer>;
  signSync(priv: Buffer, digest: Buffer): Buffer;
};

const { CryptoLib: CryptoLibNative } = NativeModules;

const CryptoLib = {
  randomNumber: CryptoLibNative.randomNumber,
  randomBytes: (length: number) => {
    return CryptoLibNative.randomBytes(length).then((bytes: string) => {
      return Buffer.from(bytes, 'base64');
    });
  },
  randomBytesSync: (length: number) => {
    return Buffer.from(CryptoLibNative.randomBytes(length), 'base64');
  },
  hash: (type: HASH, data: Buffer) => {
    return Buffer.from(
      CryptoLibNative.hash(type, data.toString('base64')),
      'base64'
    );
  },
  hmac: (type: HMAC, key: Buffer, data: Buffer) => {
    return Buffer.from(
      CryptoLibNative.hmac(
        type,
        key.toString('base64'),
        data.toString('base64')
      ),
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
    return CryptoLibNative.pbkdf2(
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
      CryptoLibNative.pbkdf2Sync(
        digest,
        Buffer.from(pass).toString('base64'),
        Buffer.from(salt).toString('base64'),
        iterations,
        keyLength
      ),
      'base64'
    );
  },
};

export const bip39 = {
  mnemonicToSeed: (mnemonic: string, passphrase: string = '') => {
    return CryptoLibNative.mnemonicToSeed(mnemonic, passphrase).then(
      (result: string) => {
        return Buffer.from(result, 'base64');
      }
    );
  },
  mnemonicToSeedSync: (mnemonic: string, passphrase: string = '') => {
    return Buffer.from(
      CryptoLibNative.mnemonicToSeedSync(mnemonic, passphrase),
      'base64'
    );
  },
  generateMnemonic: (strength: number = 12) => {
    return CryptoLibNative.generateMnemonic(strength);
  },
  validateMnemonic: (mnemonic: string) => {
    return CryptoLibNative.validateMnemonic(mnemonic) === 1;
  },
} as bip39Type;

export const secp256k1 = {
  randomPrivate: () => {
    const result = CryptoLibNative.ecdsaRandomPrivate();

    if (!result) {
      throw new Error('wrong key');
    }

    return Buffer.from(result, 'base64');
  },
  validatePublic: (pub: Buffer) => {
    return CryptoLibNative.ecdsaValidatePublic(pub.toString('base64')) === 1;
  },
  validatePrivate: (priv: Buffer) => {
    const result = CryptoLibNative.ecdsaValidatePrivate(
      priv.toString('base64')
    );
    return result === 1;
  },
  getPublic: (priv: Buffer, compact: Boolean = true) => {
    let result = null;
    if (compact) {
      result = CryptoLibNative.ecdsaGetPublic33(priv.toString('base64'));
    } else {
      result = CryptoLibNative.ecdsaGetPublic65(priv.toString('base64'));
    }

    if (!result) {
      throw new Error('wrong key');
    }

    return Buffer.from(result, 'base64');
  },
  recover: (
    sig: Buffer,
    digest: Buffer,
    recid: number,
    compact: Boolean = true
  ) => {
    const result = CryptoLibNative.ecdsaRecover(
      sig.toString('base64'),
      digest.toString('base64'),
      recid,
      compact ? 1 : 0
    );

    if (!result) {
      throw new Error('recover error');
    }

    return Buffer.from(result, 'base64');
  },
  ecdh: (
    pub: Buffer,
    priv: Buffer,
    compact: Boolean = true,
    hashfn = HASH.SHA256
  ) => {
    const result = CryptoLibNative.ecdsaEcdh(
      pub.toString('base64'),
      priv.toString('base64'),
      compact ? 1 : 0
    );

    if (!result) {
      throw new Error('recover error');
    }

    if (hashfn === undefined) {
      return Buffer.from(result, 'base64');
    }

    return CryptoLib.hash(hashfn, result);
  },
  verify: (pub: Buffer, sig: Buffer, digest: Buffer) => {
    const result = CryptoLibNative.ecdsaVerify(
      pub.toString('base64'),
      sig.toString('base64'),
      digest.toString('base64')
    );
    return result === 1;
  },
  sign: (priv: Buffer, digest: Buffer) => {
    return CryptoLibNative.ecdsaSign(
      priv.toString('base64'),
      digest.toString('base64')
    ).then((result: string) => {
      return Buffer.from(result, 'base64');
    });
  },
  signSync: (priv: Buffer, digest: Buffer) => {
    const result = CryptoLibNative.ecdsaSignSync(
      priv.toString('base64'),
      digest.toString('base64')
    );

    if (!result) {
      throw new Error('recover error');
    }

    return Buffer.from(result, 'base64');
  },
} as secp256k1Type;

export default CryptoLib as CryptoLibType;
