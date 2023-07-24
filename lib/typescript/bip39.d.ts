import { Buffer } from 'buffer';
export declare const mnemonicToSeed: (mnemonic: string, passphrase?: string) => Promise<Buffer>;
export declare const generateMnemonic: (strength?: number) => Promise<string>;
export declare const validateMnemonic: (mnemonic: string) => Promise<boolean>;
//# sourceMappingURL=bip39.d.ts.map