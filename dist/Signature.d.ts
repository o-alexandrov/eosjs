/// <reference types="node" />
import { BNInput, ec as EC } from 'elliptic';
import BN = require('bn.js');
import { Key, KeyType } from './eosjs-numeric';
import { PublicKey } from './PublicKey';
declare type WebCryptoSignatureData = Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer;
/** Represents/stores a Signature and provides easy conversion for use with `elliptic` lib */
export declare class Signature {
    private signature;
    private ec;
    constructor(signature: Key, ec: EC);
    /** Instantiate Signature from an EOSIO-format Signature */
    static fromString(sig: string, ec?: EC): Signature;
    /** Instantiate Signature from an `elliptic`-format Signature */
    static fromElliptic(ellipticSig: EC.Signature | {
        r: BN;
        s: BN;
        recoveryParam: number | null;
    }, keyType: KeyType, ec?: EC): Signature;
    /** Instantiate Signature from a Web Crypto Signature */
    static fromWebCrypto(data: WebCryptoSignatureData, webCryptoSig: ArrayBuffer, publicKey: PublicKey): Promise<Signature>;
    /** Replaced version of getRecoveryParam from `elliptic` library */
    private static getRecoveryParam;
    /** Export Signature as `elliptic`-format Signature
     * NOTE: This isn't an actual elliptic-format Signature, as ec.Signature is not exported by the library.
     * That's also why the return type is `any`.  We're *actually* returning an object with the 3 params
     * not an ec.Signature.
     * Further NOTE: @types/elliptic shows ec.Signature as exported; it is *not*.  Hence the `any`.
     */
    toElliptic(): any;
    /** Export Signature as EOSIO-format Signature */
    toString(): string;
    /** Export Signature in binary format */
    toBinary(): Uint8Array;
    /** Get key type from signature */
    getType(): KeyType;
    /** Verify a signature with a message or hashed message digest and public key */
    verify(data: BNInput, publicKey: PublicKey, shouldHash?: boolean, encoding?: BufferEncoding): boolean;
    /** Verify a Web Crypto signature with data (that matches types) and public key */
    webCryptoVerify(data: WebCryptoSignatureData, webCryptoSig: ArrayBuffer, publicKey: PublicKey): Promise<boolean>;
    /** Recover a public key from a message or hashed message digest and signature */
    recover(data: BNInput, shouldHash?: boolean, encoding?: BufferEncoding): PublicKey;
}
export {};
