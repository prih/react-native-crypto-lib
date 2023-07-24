"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.hdNodeFromSeed = exports.hdNodeDerive = exports.derivePath = void 0;
var _reactNative = require("react-native");
const {
  CryptoLib: CryptoLibNative
} = _reactNative.NativeModules;
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

const hdNodeFromSeed = (curve, seed) => {
  return CryptoLibNative.hdNodeFromSeed(curve, seed.toString('base64'));
};
exports.hdNodeFromSeed = hdNodeFromSeed;
const hdNodeDerive = (node, path) => {
  return CryptoLibNative.hdNodeDerive(node, path);
};
exports.hdNodeDerive = hdNodeDerive;
const derivePath = (node, path) => {
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
exports.derivePath = derivePath;
//# sourceMappingURL=bip32.js.map