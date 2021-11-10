/// <reference types="node" />
import { BNInput, ec as EC } from 'elliptic';
import { Key, KeyType } from './eosjs-numeric';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';
declare type WebCryptoSignatureData = Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer;
/** Represents/stores a private key and provides easy conversion for use with `elliptic` lib */
export declare class PrivateKey {
    private key;
    private ec;
    constructor(key: Key, ec: EC);
    /** Instantiate private key from an `elliptic`-format private key */
    static fromElliptic(privKey: EC.KeyPair, keyType: KeyType, ec?: EC): PrivateKey;
    /** Instantiate private key from a `CryptoKey`-format private key */
    static fromWebCrypto(privKey: CryptoKey): Promise<PrivateKey>;
    /** Instantiate private key from an EOSIO-format private key */
    static fromString(keyString: string, ec?: EC): PrivateKey;
    /** Export private key as `elliptic`-format private key */
    toElliptic(): EC.KeyPair;
    /** Export private key as `CryptoKey`-format private key */
    toWebCrypto(extractable?: boolean): Promise<CryptoKey>;
    toLegacyString(): string;
    /** Export private key as EOSIO-format private key */
    toString(): string;
    /** Get key type from key */
    getType(): KeyType;
    /** Retrieve the public key from a private key */
    getPublicKey(): PublicKey;
    /** Sign a message or hashed message digest with private key */
    sign(data: BNInput, shouldHash?: boolean, encoding?: BufferEncoding): Signature;
    /** Use Web Crypto to sign data (that matches types) with private CryptoKey */
    webCryptoSign(data: WebCryptoSignatureData): Promise<Signature>;
    /** Validate a private key */
    isValid(): boolean;
}
export {};
