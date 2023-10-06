import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
import { createHash, HASH } from './digest';

const { CryptoLib: CryptoLibNative } = NativeModules;

type SignResult = {
  signature: Buffer;
  recId: number;
};

export const ecdsaRandomPrivate = async (): Promise<Buffer> => {
  return Buffer.from(await CryptoLibNative.ecdsaRandomPrivate(), 'base64');
};

export const ecdsaValidatePrivate = (pk: Buffer): boolean => {
  const valid = CryptoLibNative.ecdsaValidatePrivate(
    pk.toString('base64')
  ) as number;
  return valid === 1;
};

export const ecdsaGetPublic = (pk: Buffer, compact = true): Buffer => {
  return Buffer.from(
    CryptoLibNative.ecdsaGetPublic(pk.toString('base64'), compact),
    'base64'
  );
};

export const ecdsaReadPublic = (pub: Buffer, compact = true): Buffer => {
  return Buffer.from(
    CryptoLibNative.ecdsaReadPublic(pub.toString('base64'), compact),
    'base64'
  );
};

export const ecdsaValidatePublic = (pub: Buffer): boolean => {
  if (pub.length !== 33 && pub.length !== 65) {
    return false;
  }
  const valid = CryptoLibNative.ecdsaValidatePublic(
    pub.toString('base64')
  ) as number;
  return valid === 1;
};

export const ecdsaRecover = (
  sign: Buffer,
  recId: number,
  digest: Buffer
): Buffer => {
  return Buffer.from(
    CryptoLibNative.ecdsaRecover(
      sign.toString('base64'),
      recId,
      digest.toString('base64')
    ),
    'base64'
  );
};

export const ecdsaEcdh = (
  pub: Buffer,
  priv: Buffer,
  compact = true,
  hash = HASH.SHA256
): Buffer => {
  const ecdh = Buffer.from(
    CryptoLibNative.ecdsaEcdh(
      pub.toString('base64'),
      priv.toString('base64'),
      compact
    ),
    'base64'
  );

  return createHash(hash, ecdh);
};

export const ecdsaVerify = (
  pub: Buffer,
  sign: Buffer,
  digest: Buffer
): boolean => {
  const valid = CryptoLibNative.ecdsaVerify(
    pub.toString('base64'),
    sign.toString('base64'),
    digest.toString('base64')
  ) as number;
  return valid === 1;
};

export const ecdsaSign = (priv: Buffer, digest: Buffer): SignResult => {
  const res = Buffer.from(
    CryptoLibNative.ecdsaSign(
      priv.toString('base64'),
      digest.toString('base64')
    ),
    'base64'
  );

  return {
    signature: res.slice(1),
    recId: Number(res[0]),
  };
};

export const ecdsaSignAsync = async (
  priv: Buffer,
  digest: Buffer
): Promise<SignResult> => {
  const sign = await CryptoLibNative.ecdsaSignAsync(
    priv.toString('base64'),
    digest.toString('base64')
  );

  const res = Buffer.from(sign, 'base64');

  return {
    signature: res.slice(1),
    recId: Number(res[0]),
  };
};
