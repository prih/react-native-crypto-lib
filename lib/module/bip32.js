import { NativeModules } from 'react-native';
const {
  CryptoLib: CryptoLibNative
} = NativeModules;
const HIGHEST_BIT = 0x80000000;
const UINT31_MAX = Math.pow(2, 31) - 1;
// const UINT32_MAX = Math.pow(2, 32) - 1;

function BIP32Path(value) {
  return value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null;
}
function UInt31(value) {
  return value >= 0 && value <= UINT31_MAX;
}

// function UInt32(value: number): Boolean {
//   return value >= 0 && value <= UINT32_MAX;
// }

export const hdNodeFromSeed = (curve, seed) => {
  return CryptoLibNative.hdNodeFromSeed(curve, seed.toString('base64'));
};
export const hdNodeDerive = (node, path) => {
  return CryptoLibNative.hdNodeDerive(node, path);
};
export const derivePath = (node, path) => {
  if (!BIP32Path(path)) {
    throw new TypeError('Missing BIP32 path');
  }
  const path_items = path.split('/');
  const path_indexes = [];
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
//# sourceMappingURL=bip32.js.map