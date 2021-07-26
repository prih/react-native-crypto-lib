import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

import * as digest from './digest';

type signType = {
  signature: Buffer;
  recid: number;
};

const { CryptoLib: CryptoLibNative } = NativeModules;

export const randomPrivate = () => {
  const result = CryptoLibNative.ecdsaRandomPrivate();

  if (!result) {
    throw new Error('wrong key');
  }

  return Buffer.from(result, 'base64');
};

export const readPublic = (pub: Buffer, compact: Boolean = true) => {
  const result = CryptoLibNative.ecdsaReadPublic(
    pub.toString('base64'),
    compact ? 1 : 0
  );

  if (!result) {
    throw new Error('wrong key');
  }

  return Buffer.from(result, 'base64');
};

export const validatePublic = (pub: Buffer) => {
  return CryptoLibNative.ecdsaValidatePublic(pub.toString('base64')) === 1;
};

export const validatePrivate = (priv: Buffer) => {
  const result = CryptoLibNative.ecdsaValidatePrivate(priv.toString('base64'));
  return result === 1;
};

export const getPublic = (priv: Buffer, compact: Boolean = true) => {
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
};

export const recover = (
  sig: Buffer,
  msg: Buffer,
  recid: number,
  compact: Boolean = true
) => {
  const result = CryptoLibNative.ecdsaRecover(
    sig.toString('base64'),
    msg.toString('base64'),
    recid,
    compact ? 1 : 0
  );

  if (!result) {
    throw new Error('recover error');
  }

  return Buffer.from(result, 'base64');
};

export const ecdh = (
  pub: Buffer,
  priv: Buffer,
  compact: Boolean = true,
  hashfn = 'sha256'
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

  return digest.createHash(hashfn, result);
};

export const verify = (pub: Buffer, sig: Buffer, msg: Buffer) => {
  const result = CryptoLibNative.ecdsaVerify(
    pub.toString('base64'),
    sig.toString('base64'),
    msg.toString('base64')
  );
  return result === 1;
};

export const sign = (priv: Buffer, msg: Buffer) => {
  return CryptoLibNative.ecdsaSign(
    priv.toString('base64'),
    msg.toString('base64')
  ).then((result: string) => {
    const sig = Buffer.from(result, 'base64');
    return {
      signature: sig.slice(1),
      recid: Number(sig[0]),
    } as signType;
  });
};

export const signSync = (priv: Buffer, msg: Buffer) => {
  const result = CryptoLibNative.ecdsaSignSync(
    priv.toString('base64'),
    msg.toString('base64')
  );

  if (!result) {
    throw new Error('recover error');
  }

  const sig = Buffer.from(result, 'base64');
  return {
    signature: sig.slice(1),
    recid: Number(sig[0]),
  } as signType;
};
