/**
 * @module WebCrypto-Sig
 */
/// <reference types="node" />
import { ec } from 'elliptic';
import { SignatureProvider, SignatureProviderArgs } from './eosjs-api-interfaces';
import { PushTransactionArgs } from './eosjs-rpc-interfaces';
import { PrivateKey, PublicKey, Signature, generateWebCryptoKeyPair, CryptoKeyPair } from './eosjs-key-conversions';
/** Construct the buffer from transaction details, web crypto will sign it */
declare const bufferFromSerializedData: (chainId: string, serializedTransaction: Uint8Array, serializedContextFreeData?: Uint8Array, e?: ec) => Buffer;
/** Signs transactions using Web Crypto API private keys */
declare class WebCryptoSignatureProvider implements SignatureProvider {
    /** Map public key to private CryptoKey. User can populate this manually or use addCryptoKeyPair(). */
    keys: Map<string, CryptoKey>;
    /** Public keys as string array. User must populate this if not using addCryptoKeyPair() */
    availableKeys: string[];
    /** Add Web Crypto KeyPair to the `SignatureProvider` */
    addCryptoKeyPair({ privateKey, publicKey }: CryptoKeyPair): Promise<void>;
    /** Public keys associated with the private keys that the `SignatureProvider` holds */
    getAvailableKeys(): Promise<string[]>;
    /** Sign a transaction */
    sign({ chainId, requiredKeys, serializedTransaction, serializedContextFreeData }: SignatureProviderArgs): Promise<PushTransactionArgs>;
}
export { generateWebCryptoKeyPair, PrivateKey, PublicKey, Signature, bufferFromSerializedData, WebCryptoSignatureProvider, };
