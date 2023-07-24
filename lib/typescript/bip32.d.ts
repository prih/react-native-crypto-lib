/// <reference types="node" />
type Bip32Curve = 'secp256k1' | 'secp256k1-decred' | 'secp256k1-groestl' | 'secp256k1-smart' | 'nist256p1' | 'ed25519' | 'ed25519-sha3' | 'ed25519-keccak' | 'curve25519';
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
export declare const hdNodeFromSeed: (curve: Bip32Curve, seed: Buffer) => HDNode;
export declare const hdNodeDerive: (node: HDNode, path: number[]) => HDNode;
export declare const derivePath: (node: HDNode, path: string) => HDNode;
export {};
//# sourceMappingURL=bip32.d.ts.map