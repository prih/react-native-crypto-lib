/// <reference types="node" />
import { Buffer } from 'buffer';
export declare function getPublic(priv: Buffer): Buffer;
export declare function sign(priv: Buffer, digest: Buffer): Buffer;
export declare function signAsync(priv: Buffer, digest: Buffer): Promise<Buffer>;
export declare function verify(pub: Buffer, sig: Buffer, digest: Buffer): boolean;
//# sourceMappingURL=schnorr.d.ts.map