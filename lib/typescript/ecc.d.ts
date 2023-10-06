export interface XOnlyPointAddTweakResult {
    parity: 1 | 0;
    xOnlyPubkey: Uint8Array;
}
export interface TinySecp256k1Interface {
    isPoint(p: Uint8Array): boolean;
    isXOnlyPoint(p: Uint8Array): boolean;
    xOnlyPointAddTweak(p: Uint8Array, tweak: Uint8Array): XOnlyPointAddTweakResult | null;
}
declare const _default: TinySecp256k1Interface;
export default _default;
//# sourceMappingURL=ecc.d.ts.map