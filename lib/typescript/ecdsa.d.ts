/// <reference types="node" />
import { Buffer } from 'buffer';
import { HASH } from './digest';
type SignResult = {
    signature: Buffer;
    recId: number;
};
export declare const ecdsaRandomPrivate: () => Promise<Buffer>;
export declare const ecdsaValidatePrivate: (pk: Buffer) => boolean;
export declare const ecdsaGetPublic: (pk: Buffer, compact?: boolean) => Buffer;
export declare const ecdsaReadPublic: (pub: Buffer, compact?: boolean) => Buffer;
export declare const ecdsaValidatePublic: (pub: Buffer) => boolean;
export declare const ecdsaRecover: (sign: Buffer, recId: number, digest: Buffer) => Buffer;
export declare const ecdsaEcdh: (pub: Buffer, priv: Buffer, compact?: boolean, hash?: HASH) => Buffer;
export declare const ecdsaVerify: (pub: Buffer, sign: Buffer, digest: Buffer) => boolean;
export declare const ecdsaSign: (priv: Buffer, digest: Buffer) => SignResult;
export {};
//# sourceMappingURL=ecdsa.d.ts.map