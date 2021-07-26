import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';
import * as digest from './digest';
import * as secp256k1 from './secp256k1';

const { CryptoLib: CryptoLibNative } = NativeModules;

enum DERIVE {
  PRIVATE = 0,
  PUBLIC = 1,
}

type HDNodeData = {
  depth: number;
  child_num: number;
  chain_code: Buffer;
  private_key: Buffer;
  public_key: Buffer;
  fingerprint: Buffer;
};

// function debugPrint(data: HDNodeData) {
//   console.log('----->');
//   console.log('depth:', data.depth);
//   console.log('child_num:', data.child_num);
//   console.log('chain_code:', data.chain_code.toString('hex'));
//   console.log('private_key:', data.private_key.toString('hex'));
//   console.log('public_key:', data.public_key.toString('hex'));
//   console.log('fingerprint:', data.fingerprint);
//   console.log('<-----/');
// }

const bip32Native = {
  fromSeed: (seed: Buffer) => {
    const result = CryptoLibNative.hdNodeFromSeed(seed.toString('base64'));

    if (!result) {
      throw new Error('seed error');
    }

    const data = Buffer.from(result, 'base64');

    const hdnode_data = {
      depth: data.slice(0, 4).readUInt32LE(),
      child_num: data.slice(4, 8).readUInt32LE(),
      chain_code: data.slice(8, 40),
      private_key: data.slice(40, 72),
      public_key: data.slice(72, 105),
      fingerprint: data.slice(105, 109).reverse(),
    } as HDNodeData;

    return hdnode_data;
  },
  derive: (data: HDNodeData, i: number = 0, type = DERIVE.PRIVATE) => {
    // console.log('derive:', i, type);
    // debugPrint(data);

    const depth = Buffer.alloc(4);
    depth.writeUInt32LE(data.depth);
    const child_num = Buffer.alloc(4);
    child_num.writeUInt32LE(data.child_num);

    const buf = Buffer.concat([
      depth,
      child_num,
      data.chain_code,
      data.private_key,
      data.public_key,
      Buffer.alloc(4, 0),
    ]);

    const result = CryptoLibNative.hdNodeDerive(
      type,
      buf.toString('base64'),
      i
    );

    if (!result) {
      throw new Error('seed error');
    }

    const new_data = Buffer.from(result, 'base64');

    const hdnode_data = {
      depth: new_data.slice(0, 4).readUInt32LE(),
      child_num: new_data.slice(4, 8).readUInt32LE(),
      chain_code: new_data.slice(8, 40),
      private_key: new_data.slice(40, 72),
      public_key: new_data.slice(72, 105),
      fingerprint: new_data.slice(105, 109).reverse(),
    } as HDNodeData;

    // console.log('derive result:');
    // debugPrint(hdnode_data);

    return hdnode_data;
  },
};

const HIGHEST_BIT = 0x80000000;
const UINT31_MAX = Math.pow(2, 31) - 1;
const UINT32_MAX = Math.pow(2, 32) - 1;

function BIP32Path(value: string): Boolean {
  return value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null;
}
function UInt31(value: number): Boolean {
  return value >= 0 && value <= UINT31_MAX;
}
function UInt32(value: number): Boolean {
  return value >= 0 && value <= UINT32_MAX;
}

export class BIP32 {
  private __D: Buffer | undefined;
  private __Q: Buffer | undefined;
  public chainCode: Buffer;
  private __DEPTH: number;
  private __INDEX: number;
  private __PARENT_FINGERPRINT: Buffer | undefined;
  private __FINGERPRINT: Buffer | undefined;
  private lowR: Boolean = false;

  constructor(
    __D: Buffer | undefined,
    __Q: Buffer | undefined,
    chainCode: Buffer,
    __DEPTH = 0,
    __INDEX = 0,
    __PARENT_FINGERPRINT: Buffer | undefined,
    __FINGERPRINT: Buffer | undefined
  ) {
    this.__D = __D;
    this.__Q = __Q;
    this.chainCode = chainCode;
    this.__DEPTH = __DEPTH;
    this.__INDEX = __INDEX;
    this.__PARENT_FINGERPRINT = __PARENT_FINGERPRINT;
    this.__FINGERPRINT = __FINGERPRINT;
  }
  get depth() {
    return this.__DEPTH;
  }
  get index() {
    return this.__INDEX;
  }
  get parentFingerprint() {
    return this.__PARENT_FINGERPRINT;
  }
  get publicKey() {
    if (this.__Q === undefined && this.__D) {
      const pub = CryptoLibNative.ecdsaGetPublic33(this.__D.toString('base64'));
      this.__Q = Buffer.from(pub, 'base64');
    }
    return this.__Q;
  }
  get privateKey() {
    return this.__D;
  }
  get fingerprint() {
    if (!this.__FINGERPRINT && this.publicKey) {
      const id = digest.createHash('hash160', this.publicKey);
      this.__FINGERPRINT = id.slice(0, 4);
    }
    return this.__FINGERPRINT;
  }
  get compressed() {
    return true;
  }
  // Private === not neutered
  // Public === neutered
  isNeutered() {
    return this.__D === undefined;
  }
  // neutered() {
  //   return fromPublicKeyLocal(
  //     this.publicKey,
  //     this.chainCode,
  //     this.network,
  //     this.depth,
  //     this.index,
  //     this.parentFingerprint
  //   );
  // }
  // toBase58() {
  //   const network = this.network;
  //   const version = !this.isNeutered()
  //     ? network.bip32.private
  //     : network.bip32.public;
  //   const buffer = Buffer.allocUnsafe(78);
  //   // 4 bytes: version bytes
  //   buffer.writeUInt32BE(version, 0);
  //   // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
  //   buffer.writeUInt8(this.depth, 4);
  //   // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  //   buffer.writeUInt32BE(this.parentFingerprint, 5);
  //   // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  //   // This is encoded in big endian. (0x00000000 if master key)
  //   buffer.writeUInt32BE(this.index, 9);
  //   // 32 bytes: the chain code
  //   this.chainCode.copy(buffer, 13);
  //   // 33 bytes: the public key or private key data
  //   if (!this.isNeutered()) {
  //     // 0x00 + k for private keys
  //     buffer.writeUInt8(0, 45);
  //     this.privateKey.copy(buffer, 46);
  //     // 33 bytes: the public key
  //   } else {
  //     // X9.62 encoding for public keys
  //     this.publicKey.copy(buffer, 45);
  //   }
  //   return bs58check.encode(buffer);
  // }

  // toWIF() {
  //   if (!this.privateKey) throw new TypeError('Missing private key');
  //   return wif.encode(this.network.wif, this.privateKey, true);
  // }

  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
  derive(index: number): BIP32 {
    if (!UInt32(index)) {
      throw new TypeError('Missing index uint32');
    }
    const isHardened = index >= HIGHEST_BIT;

    if (isHardened) {
      if (this.isNeutered()) {
        throw new TypeError('Missing private key for hardened child key');
      }

      const data = bip32Native.derive(
        {
          depth: this.__DEPTH,
          child_num: this.__INDEX,
          chain_code: this.chainCode,
          private_key: this.__D || Buffer.alloc(32, 0),
          public_key: Buffer.alloc(33, 0),
          fingerprint: this.fingerprint || Buffer.alloc(4, 0),
        },
        index,
        DERIVE.PRIVATE
      );

      return fromKeyLocal(
        data.private_key,
        data.public_key,
        data.chain_code,
        data.depth,
        data.child_num,
        this.fingerprint,
        data.fingerprint
      );
    } else {
      let data: HDNodeData;

      if (!this.isNeutered()) {
        data = bip32Native.derive(
          {
            depth: this.__DEPTH,
            child_num: this.__INDEX,
            chain_code: this.chainCode,
            private_key: this.__D || Buffer.alloc(32, 0),
            public_key: this.__Q || Buffer.alloc(33, 0),
            fingerprint: this.fingerprint || Buffer.alloc(4, 0),
          },
          index,
          DERIVE.PRIVATE
        );

        return fromKeyLocal(
          data.private_key,
          data.public_key,
          data.chain_code,
          data.depth,
          data.child_num,
          this.fingerprint,
          data.fingerprint
        );
      } else {
        data = bip32Native.derive(
          {
            depth: this.__DEPTH,
            child_num: this.__INDEX,
            chain_code: this.chainCode,
            private_key: Buffer.alloc(32, 0),
            public_key: this.__Q || Buffer.alloc(33, 0),
            fingerprint: this.fingerprint || Buffer.alloc(4, 0),
          },
          index,
          DERIVE.PUBLIC
        );

        return fromKeyLocal(
          undefined,
          data.public_key,
          data.chain_code,
          data.depth,
          data.child_num,
          this.fingerprint,
          data.fingerprint
        );
      }
    }
  }
  deriveHardened(index: number): BIP32 {
    if (!UInt31(index)) {
      throw new TypeError('Missing index uint31');
    }
    // Only derives hardened private keys by default
    return this.derive(index + HIGHEST_BIT);
  }
  derivePath(path: string) {
    if (!BIP32Path(path)) {
      throw new TypeError('Missing BIP32 path');
    }

    let splitPath = path.split('/');
    if (splitPath[0] === 'm') {
      if (this.parentFingerprint)
        throw new TypeError('Expected master, got child');
      splitPath = splitPath.slice(1);
    }
    return splitPath.reduce((prevHd: BIP32, indexStr: string) => {
      let index;
      if (indexStr.slice(-1) === `'`) {
        index = parseInt(indexStr.slice(0, -1), 10);
        return prevHd.deriveHardened(index);
      } else {
        index = parseInt(indexStr, 10);
        return prevHd.derive(index);
      }
    }, this);
  }
  sign(hash: Buffer, lowR: Boolean = false) {
    if (!this.privateKey) throw new Error('Missing private key');
    if (lowR === undefined) lowR = this.lowR;
    if (lowR === false) {
      return secp256k1.signSync(this.privateKey, hash).signature;
    } else {
      throw new Error('lowR is now allowed');
      // let sig = secp256k1.signSync(this.privateKey, hash);
      // const extraData = Buffer.alloc(32, 0);
      // let counter = 0;
      // // if first try is lowR, skip the loop
      // // for second try and on, add extra entropy counting up
      // while (sig.signature[0] > 0x7f) {
      //   counter++;
      //   extraData.writeUIntLE(counter, 0, 6);
      //   sig = ecc.signWithEntropy(hash, this.privateKey, extraData);
      // }
      // return sig;
    }
  }
  verify(hash: Buffer, signature: Buffer) {
    if (!this.publicKey) {
      throw new Error('Missing public key');
    }
    return secp256k1.verify(this.publicKey, signature, hash);
  }
}

export function fromKeyLocal(
  privateKey: Buffer | undefined,
  publicKey: Buffer | undefined,
  chainCode: Buffer,
  depth: number,
  index: number,
  parentFingerprint: Buffer | undefined,
  fingerprint: Buffer | undefined
) {
  return new BIP32(
    privateKey,
    publicKey,
    chainCode,
    depth,
    index,
    parentFingerprint,
    fingerprint
  );
}

export function fromSeed(seed: Buffer) {
  const data = bip32Native.fromSeed(seed);

  return fromKeyLocal(
    data.private_key,
    data.public_key,
    data.chain_code,
    data.depth,
    data.child_num,
    undefined,
    data.fingerprint
  );
}
