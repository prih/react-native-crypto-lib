import { Buffer } from 'buffer';
export declare enum HASH {
    SHA1 = 0,
    SHA256 = 1,
    SHA512 = 2,
    SHA3_256 = 3,
    SHA3_512 = 4,
    KECCAK256 = 5,
    KECCAK512 = 6,
    RIPEMD160 = 7,
    HASH256 = 8,
    HASH160 = 9
}
export declare enum HMAC_HASH {
    SHA256 = 1,
    SHA512 = 2
}
export declare enum PBKDF2_HASH {
    SHA256 = 1,
    SHA512 = 2
}
export declare const createHash: (type: HASH, data: Buffer) => Buffer;
export declare const createHmac: (type: HMAC_HASH, key: Buffer, data: Buffer) => Buffer;
export declare const pbkdf2: (pass: string | Buffer, salt: string | Buffer, iterations?: number, keyLength?: number, digest?: PBKDF2_HASH) => Promise<Buffer>;
//# sourceMappingURL=digest.d.ts.map