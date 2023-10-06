import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

const { CryptoLib: CryptoLibNative } = NativeModules;

export function getPublic(priv: Buffer): Buffer {
  return Buffer.from(
    CryptoLibNative.schnorrGetPublic(priv.toString('base64')),
    'base64'
  );
}

export function sign(priv: Buffer, digest: Buffer): Buffer {
  return Buffer.from(
    CryptoLibNative.schnorrSign(
      priv.toString('base64'),
      digest.toString('base64')
    ),
    'base64'
  );
}

export async function signAsync(priv: Buffer, digest: Buffer): Promise<Buffer> {
  return Buffer.from(
    await CryptoLibNative.schnorrSignAsync(
      priv.toString('base64'),
      digest.toString('base64')
    ),
    'base64'
  );
}

export function verify(pub: Buffer, sig: Buffer, digest: Buffer): boolean {
  const valid = CryptoLibNative.schnorrVerify(
    pub.toString('base64'),
    sig.toString('base64'),
    digest.toString('base64')
  ) as number;
  return valid === 1;
}

export function tweakPublicKey(pub: Buffer, root?: Buffer): Buffer {
  return Buffer.from(
    CryptoLibNative.schnorrTweakPublic(
      pub.toString('base64'),
      root ? root.toString('base64') : ''
    ),
    'base64'
  );
}

export function tweakPrivateKey(priv: Buffer, root?: Buffer): Buffer {
  return Buffer.from(
    CryptoLibNative.schnorrTweakPrivate(
      priv.toString('base64'),
      root ? root.toString('base64') : ''
    ),
    'base64'
  );
}
