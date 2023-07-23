import { NativeModules } from 'react-native';

const { CryptoLib: CryptoLibNative } = NativeModules;

type Bip32Curve =
  | 'secp256k1'
  | 'secp256k1-decred'
  | 'secp256k1-groestl'
  | 'secp256k1-smart'
  | 'nist256p1'
  | 'ed25519'
  | 'ed25519-sha3'
  | 'ed25519-keccak'
  | 'curve25519';

type HDNode = {
  depth: number;
  child_num: number;
  chain_code: string;
  private_key?: string;
  public_key?: string;
  fingerprint: number;
  curve: Bip32Curve;
  private_derive: boolean;
};

const HIGHEST_BIT = 0x80000000;
const UINT31_MAX = Math.pow(2, 31) - 1;
// const UINT32_MAX = Math.pow(2, 32) - 1;

function BIP32Path(value: string): Boolean {
  return value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null;
}

function UInt31(value: number): Boolean {
  return value >= 0 && value <= UINT31_MAX;
}

// function UInt32(value: number): Boolean {
//   return value >= 0 && value <= UINT32_MAX;
// }

export const hdNodeFromSeed = (curve: Bip32Curve, seed: Buffer): HDNode => {
  return CryptoLibNative.hdNodeFromSeed(curve, seed.toString('base64'));
};

export const hdNodeDerive = (node: HDNode, path: number[]): HDNode => {
  return CryptoLibNative.hdNodeDerive(node, path);
};

export const derivePath = (node: HDNode, path: string): HDNode => {
  if (!BIP32Path(path)) {
    throw new TypeError('Missing BIP32 path');
  }

  const path_items: string[] = path.split('/');
  const path_indexes: number[] = [];

  for (let item of path_items) {
    if (item === 'm') {
      if (node.depth !== 0) {
        throw new TypeError('Expected master, got child');
      }
      continue;
    }

    if (item.slice(-1) === `'`) {
      const index = parseInt(item.slice(0, -1), 10);
      if (!UInt31(index)) {
        throw new TypeError('Missing index uint31');
      }
      path_indexes.push(HIGHEST_BIT + index);
    } else {
      const index = parseInt(item, 10);
      if (!UInt31(index)) {
        throw new TypeError('Missing index uint31');
      }
      path_indexes.push(index);
    }
  }

  return hdNodeDerive(node, path_indexes);
};
