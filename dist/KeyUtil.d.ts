import { ec as EC } from 'elliptic';
import { KeyType } from './eosjs-numeric';
import { PublicKey } from './PublicKey';
import { PrivateKey } from './PrivateKey';
export interface CryptoKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}
export declare const generateKeyPair: (type: KeyType, options?: {
    secureEnv?: boolean;
    ecOptions?: EC.GenKeyPairOptions;
}) => {
    publicKey: PublicKey;
    privateKey: PrivateKey;
};
/** Construct a p256/secp256r1 CryptoKeyPair from Web Crypto
 * Note: While creating a key that is not extractable means that it would not be possible
 * to convert the private key to string, it is not necessary to have the key extractable
 * for the Web Crypto Signature Provider.  Additionally, creating a key that is extractable
 * introduces security concerns.  For this reason, this function only creates CryptoKeyPairs
 * where the private key is not extractable and the public key is extractable.
 */
export declare const generateWebCryptoKeyPair: (keyUsage?: KeyUsage[]) => Promise<CryptoKeyPair>;
