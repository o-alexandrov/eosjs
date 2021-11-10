"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
/* eslint-disable @typescript-eslint/no-floating-promises */
var elliptic_1 = require("elliptic");
var _a = require('crypto').webcrypto, subtle = _a.subtle, CryptoKey = _a.CryptoKey;
var eosjs_key_conversions_1 = require("../eosjs-key-conversions");
var eosjs_jssig_1 = require("../eosjs-jssig");
var eosjs_numeric_1 = require("../eosjs-numeric");
var eosjs_webcrypto_sig_1 = require("../eosjs-webcrypto-sig");
describe('WebCryptoSignatureProvider', function () {
    it('generates a private and public key pair', function () { return __awaiter(void 0, void 0, void 0, function () {
        var _a, privateKey, publicKey;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, (0, eosjs_key_conversions_1.generateWebCryptoKeyPair)()];
                case 1:
                    _a = _b.sent(), privateKey = _a.privateKey, publicKey = _a.publicKey;
                    expect(privateKey).toBeInstanceOf(CryptoKey);
                    expect(privateKey.type).toEqual('private');
                    expect(privateKey.extractable).toBeFalsy();
                    expect(privateKey.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-256' });
                    expect(privateKey.usages).toEqual(['sign']);
                    expect(publicKey).toBeInstanceOf(CryptoKey);
                    expect(publicKey.type).toEqual('public');
                    expect(publicKey.extractable).toBeTruthy();
                    expect(publicKey.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-256' });
                    expect(publicKey.usages).toEqual(['verify']);
                    return [2 /*return*/];
            }
        });
    }); });
    it('generates a private and public key pair with no usages', function () { return __awaiter(void 0, void 0, void 0, function () {
        var _a, privateKey, publicKey;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, (0, eosjs_key_conversions_1.generateWebCryptoKeyPair)([])];
                case 1:
                    _a = _b.sent(), privateKey = _a.privateKey, publicKey = _a.publicKey;
                    expect(privateKey.usages.length).toEqual(0);
                    expect(publicKey).toBeInstanceOf(CryptoKey);
                    expect(publicKey.usages.length).toEqual(0);
                    return [2 /*return*/];
            }
        });
    }); });
    it('fails to convert private non-extractable CryptoKey to PrivateKey', function () { return __awaiter(void 0, void 0, void 0, function () {
        var privateKey, convertPrivateKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, (0, eosjs_key_conversions_1.generateWebCryptoKeyPair)()];
                case 1:
                    privateKey = (_a.sent()).privateKey;
                    convertPrivateKey = function (priv) { return __awaiter(void 0, void 0, void 0, function () {
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0: return [4 /*yield*/, eosjs_key_conversions_1.PrivateKey.fromWebCrypto(priv)];
                                case 1: return [2 /*return*/, _a.sent()];
                            }
                        });
                    }); };
                    expect(convertPrivateKey(privateKey)).rejects.toThrow('Crypto Key is not extractable');
                    return [2 /*return*/];
            }
        });
    }); });
    it('converts private extractable CryptoKey to PrivateKey', function () { return __awaiter(void 0, void 0, void 0, function () {
        var privateKey, priv;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, subtle.generateKey({
                        name: 'ECDSA',
                        namedCurve: 'P-256'
                    }, true, ['sign', 'verify'])];
                case 1:
                    privateKey = (_a.sent()).privateKey;
                    return [4 /*yield*/, eosjs_key_conversions_1.PrivateKey.fromWebCrypto(privateKey)];
                case 2:
                    priv = _a.sent();
                    expect(priv).toBeInstanceOf(eosjs_key_conversions_1.PrivateKey);
                    return [2 /*return*/];
            }
        });
    }); });
    it('fails to convert public non-extractable CryptoKey to PublicKey', function () { return __awaiter(void 0, void 0, void 0, function () {
        var pub, publicKey, convertPublicKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    pub = (0, eosjs_key_conversions_1.generateKeyPair)(eosjs_numeric_1.KeyType.r1, { secureEnv: true }).publicKey;
                    return [4 /*yield*/, pub.toWebCrypto(false)];
                case 1:
                    publicKey = _a.sent();
                    expect(publicKey.extractable).toBeFalsy();
                    convertPublicKey = function (pubKey) { return __awaiter(void 0, void 0, void 0, function () {
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0: return [4 /*yield*/, eosjs_key_conversions_1.PublicKey.fromWebCrypto(pubKey)];
                                case 1: return [2 /*return*/, _a.sent()];
                            }
                        });
                    }); };
                    expect(convertPublicKey(publicKey)).rejects.toThrow('Crypto Key is not extractable');
                    return [2 /*return*/];
            }
        });
    }); });
    it('converts public extractable CryptoKey to PublicKey', function () { return __awaiter(void 0, void 0, void 0, function () {
        var publicKey, pub;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, (0, eosjs_key_conversions_1.generateWebCryptoKeyPair)()];
                case 1:
                    publicKey = (_a.sent()).publicKey;
                    return [4 /*yield*/, eosjs_key_conversions_1.PublicKey.fromWebCrypto(publicKey)];
                case 2:
                    pub = _a.sent();
                    expect(pub).toBeInstanceOf(eosjs_key_conversions_1.PublicKey);
                    return [2 /*return*/];
            }
        });
    }); });
    it('builds keys/availableKeys list from CryptoKeyPair with `addCryptoKeyPair`', function () { return __awaiter(void 0, void 0, void 0, function () {
        var provider, cryptoKeyPair, keys;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    provider = new eosjs_webcrypto_sig_1.WebCryptoSignatureProvider();
                    return [4 /*yield*/, (0, eosjs_key_conversions_1.generateWebCryptoKeyPair)()];
                case 1:
                    cryptoKeyPair = _a.sent();
                    return [4 /*yield*/, provider.addCryptoKeyPair(cryptoKeyPair)];
                case 2:
                    _a.sent();
                    return [4 /*yield*/, provider.getAvailableKeys()];
                case 3:
                    keys = _a.sent();
                    expect(provider.keys.size).toEqual(1);
                    expect(keys.length).toEqual(1);
                    return [2 /*return*/];
            }
        });
    }); });
    it('signs a transaction', function () { return __awaiter(void 0, void 0, void 0, function () {
        var provider, _a, privateKey, publicKey, pub, pubStr, chainId, requiredKeys, serializedTransaction, signOutput;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    provider = new eosjs_webcrypto_sig_1.WebCryptoSignatureProvider();
                    return [4 /*yield*/, (0, eosjs_key_conversions_1.generateWebCryptoKeyPair)()];
                case 1:
                    _a = _b.sent(), privateKey = _a.privateKey, publicKey = _a.publicKey;
                    return [4 /*yield*/, provider.addCryptoKeyPair({ privateKey: privateKey, publicKey: publicKey })];
                case 2:
                    _b.sent();
                    return [4 /*yield*/, eosjs_key_conversions_1.PublicKey.fromWebCrypto(publicKey)];
                case 3:
                    pub = _b.sent();
                    pubStr = pub.toString();
                    chainId = '12345';
                    requiredKeys = [pubStr];
                    serializedTransaction = new Uint8Array([
                        0, 16, 32, 128, 255,
                    ]);
                    return [4 /*yield*/, provider.sign({ chainId: chainId, requiredKeys: requiredKeys, serializedTransaction: serializedTransaction })];
                case 4:
                    signOutput = _b.sent();
                    expect(signOutput).toEqual({
                        signatures: expect.any(Array),
                        serializedTransaction: serializedTransaction,
                        serializedContextFreeData: undefined
                    });
                    return [2 /*return*/];
            }
        });
    }); });
    it('verify a signature constructed by Web Crypto', function () { return __awaiter(void 0, void 0, void 0, function () {
        var provider, _a, privateKey, publicKey, pub, pubStr, chainId, requiredKeys, serializedTransaction, signOutput, signature;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    provider = new eosjs_webcrypto_sig_1.WebCryptoSignatureProvider();
                    return [4 /*yield*/, (0, eosjs_key_conversions_1.generateWebCryptoKeyPair)()];
                case 1:
                    _a = _b.sent(), privateKey = _a.privateKey, publicKey = _a.publicKey;
                    return [4 /*yield*/, provider.addCryptoKeyPair({ privateKey: privateKey, publicKey: publicKey })];
                case 2:
                    _b.sent();
                    return [4 /*yield*/, eosjs_key_conversions_1.PublicKey.fromWebCrypto(publicKey)];
                case 3:
                    pub = _b.sent();
                    pubStr = pub.toString();
                    chainId = '12345';
                    requiredKeys = [pubStr];
                    serializedTransaction = new Uint8Array([
                        0, 16, 32, 128, 255,
                    ]);
                    return [4 /*yield*/, provider.sign({ chainId: chainId, requiredKeys: requiredKeys, serializedTransaction: serializedTransaction })];
                case 4:
                    signOutput = _b.sent();
                    signature = eosjs_key_conversions_1.Signature.fromString(signOutput.signatures[0]);
                    expect(signature.verify((0, eosjs_jssig_1.digestFromSerializedData)(chainId, serializedTransaction), pub, false)).toEqual(true);
                    return [2 /*return*/];
            }
        });
    }); });
    it('confirm a keyPair constructed from elliptic can be converted reciprocally', function () { return __awaiter(void 0, void 0, void 0, function () {
        var ec, keyPairEc, privateKey, publicKey, webCryptoPriv, webCryptoPub, exportedPrivateKey, exportedPublicKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    ec = new elliptic_1.ec('p256');
                    keyPairEc = ec.genKeyPair();
                    privateKey = eosjs_key_conversions_1.PrivateKey.fromElliptic(keyPairEc, eosjs_numeric_1.KeyType.r1, ec);
                    publicKey = eosjs_key_conversions_1.PublicKey.fromElliptic(keyPairEc, eosjs_numeric_1.KeyType.r1, ec);
                    return [4 /*yield*/, privateKey.toWebCrypto(true)];
                case 1:
                    webCryptoPriv = _a.sent();
                    return [4 /*yield*/, publicKey.toWebCrypto(true)];
                case 2:
                    webCryptoPub = _a.sent();
                    return [4 /*yield*/, eosjs_key_conversions_1.PrivateKey.fromWebCrypto(webCryptoPriv)];
                case 3:
                    exportedPrivateKey = _a.sent();
                    return [4 /*yield*/, eosjs_key_conversions_1.PublicKey.fromWebCrypto(webCryptoPub)];
                case 4:
                    exportedPublicKey = _a.sent();
                    expect(exportedPrivateKey.toString()).toEqual(privateKey.toString());
                    expect(exportedPublicKey.toString()).toEqual(publicKey.toString());
                    expect(publicKey.isValid()).toBeTruthy();
                    expect(exportedPublicKey.isValid()).toBeTruthy();
                    return [2 /*return*/];
            }
        });
    }); });
    it('confirm a keyPair constructed from Web Crypto can be converted reciprocally', function () { return __awaiter(void 0, void 0, void 0, function () {
        var ec, _a, privateKey, publicKey, priv, pub, privEc, pubEc, exportedPrivateKey, exportedPublicKey;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    ec = new elliptic_1.ec('p256');
                    return [4 /*yield*/, subtle.generateKey({
                            name: 'ECDSA',
                            namedCurve: 'P-256'
                        }, true, ['sign', 'verify'])];
                case 1:
                    _a = _b.sent(), privateKey = _a.privateKey, publicKey = _a.publicKey;
                    return [4 /*yield*/, eosjs_key_conversions_1.PrivateKey.fromWebCrypto(privateKey)];
                case 2:
                    priv = _b.sent();
                    return [4 /*yield*/, eosjs_key_conversions_1.PublicKey.fromWebCrypto(publicKey)];
                case 3:
                    pub = _b.sent();
                    privEc = priv.toElliptic();
                    pubEc = pub.toElliptic();
                    exportedPrivateKey = eosjs_key_conversions_1.PrivateKey.fromElliptic(privEc, eosjs_numeric_1.KeyType.r1, ec);
                    exportedPublicKey = eosjs_key_conversions_1.PublicKey.fromElliptic(pubEc, eosjs_numeric_1.KeyType.r1, ec);
                    expect(exportedPrivateKey.toString()).toEqual(priv.toString());
                    expect(exportedPublicKey.toString()).toEqual(pub.toString());
                    expect(pub.isValid()).toBeTruthy();
                    expect(exportedPublicKey.isValid()).toBeTruthy();
                    return [2 /*return*/];
            }
        });
    }); });
    it('Ensure Web Crypt sign, recover, verify flow works', function () { return __awaiter(void 0, void 0, void 0, function () {
        var _a, privateKey, publicKey, priv, pub, dataAsString, enc, encoded, sig, recoveredPub, valid;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, subtle.generateKey({
                        name: 'ECDSA',
                        namedCurve: 'P-256'
                    }, true, ['sign', 'verify'])];
                case 1:
                    _a = _b.sent(), privateKey = _a.privateKey, publicKey = _a.publicKey;
                    return [4 /*yield*/, eosjs_key_conversions_1.PrivateKey.fromWebCrypto(privateKey)];
                case 2:
                    priv = _b.sent();
                    return [4 /*yield*/, eosjs_key_conversions_1.PublicKey.fromWebCrypto(publicKey)];
                case 3:
                    pub = _b.sent();
                    dataAsString = 'some string';
                    enc = new TextEncoder();
                    encoded = enc.encode(dataAsString);
                    return [4 /*yield*/, priv.webCryptoSign(encoded)];
                case 4:
                    sig = _b.sent();
                    recoveredPub = sig.recover(encoded, true);
                    expect(recoveredPub.toString()).toEqual(pub.toString());
                    expect(recoveredPub.isValid()).toBeTruthy();
                    valid = sig.verify(encoded, recoveredPub, true);
                    expect(valid).toEqual(true);
                    return [2 /*return*/];
            }
        });
    }); });
});
//# sourceMappingURL=eosjs-webcrypto-sig.test.js.map