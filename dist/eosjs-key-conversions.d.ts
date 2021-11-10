/// <reference types="node" />
export { PrivateKey } from './PrivateKey';
export { PublicKey } from './PublicKey';
export { Signature } from './Signature';
export { generateKeyPair, generateWebCryptoKeyPair, CryptoKeyPair, } from './KeyUtil';
export declare const sha256: (data: string | Buffer) => number[] | string;
