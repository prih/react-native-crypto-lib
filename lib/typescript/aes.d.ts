/// <reference types="node" />
import { Buffer } from 'buffer';
export declare enum PADDING_MODE {
    ZERO = 0,
    PKCS7 = 1
}
export declare function encrypt(key: Buffer, iv: Buffer, data: Buffer, mode?: PADDING_MODE): Promise<Buffer>;
export declare function decrypt(key: Buffer, iv: Buffer, data: Buffer, mode?: PADDING_MODE): Promise<Buffer>;
//# sourceMappingURL=aes.d.ts.map