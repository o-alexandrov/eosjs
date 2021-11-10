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
exports.PrivateKey = void 0;
var elliptic_1 = require("elliptic");
var eosjs_numeric_1 = require("./eosjs-numeric");
var PublicKey_1 = require("./PublicKey");
var Signature_1 = require("./Signature");
var crypto = (typeof (window) !== 'undefined' ? window.crypto : require('crypto').webcrypto);
/** Represents/stores a private key and provides easy conversion for use with `elliptic` lib */
var PrivateKey = /** @class */ (function () {
    function PrivateKey(key, ec) {
        this.key = key;
        this.ec = ec;
    }
    /** Instantiate private key from an `elliptic`-format private key */
    PrivateKey.fromElliptic = function (privKey, keyType, ec) {
        if (!ec) {
            if (keyType === eosjs_numeric_1.KeyType.k1) {
                ec = new elliptic_1.ec('secp256k1');
            }
            else {
                ec = new elliptic_1.ec('p256');
            }
        }
        return new PrivateKey({
            type: keyType,
            data: privKey.getPrivate().toArrayLike(Buffer, 'be', 32),
        }, ec);
    };
    /** Instantiate private key from a `CryptoKey`-format private key */
    PrivateKey.fromWebCrypto = function (privKey) {
        return __awaiter(this, void 0, void 0, function () {
            var ec, extractedArrayBuffer, extractedDecoded, derHex, privateKeyHex, privateKeyEc;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (privKey.extractable === false) {
                            throw new Error('Crypto Key is not extractable');
                        }
                        ec = new elliptic_1.ec('p256');
                        return [4 /*yield*/, crypto.subtle.exportKey('pkcs8', privKey)];
                    case 1:
                        extractedArrayBuffer = _a.sent();
                        extractedDecoded = (0, eosjs_numeric_1.arrayToString)(extractedArrayBuffer);
                        derHex = Buffer.from(extractedDecoded, 'binary').toString('hex');
                        privateKeyHex = derHex.replace('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420', '');
                        privateKeyHex = privateKeyHex.substring(0, privateKeyHex.indexOf('a144034200'));
                        privateKeyEc = ec.keyFromPrivate(privateKeyHex, 'hex');
                        return [2 /*return*/, PrivateKey.fromElliptic(privateKeyEc, eosjs_numeric_1.KeyType.r1, ec)];
                }
            });
        });
    };
    /** Instantiate private key from an EOSIO-format private key */
    PrivateKey.fromString = function (keyString, ec) {
        var privateKey = (0, eosjs_numeric_1.stringToPrivateKey)(keyString);
        if (!ec) {
            if (privateKey.type === eosjs_numeric_1.KeyType.k1) {
                ec = new elliptic_1.ec('secp256k1');
            }
            else {
                ec = new elliptic_1.ec('p256');
            }
        }
        return new PrivateKey(privateKey, ec);
    };
    /** Export private key as `elliptic`-format private key */
    PrivateKey.prototype.toElliptic = function () {
        return this.ec.keyFromPrivate(this.key.data);
    };
    /** Export private key as `CryptoKey`-format private key */
    PrivateKey.prototype.toWebCrypto = function (extractable) {
        if (extractable === void 0) { extractable = false; }
        return __awaiter(this, void 0, void 0, function () {
            var privateKeyEc, privateKeyHex, publicKey, publicKeyEc, publicKeyHex, derHex, derBinary, pkcs8ArrayBuffer;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        privateKeyEc = this.toElliptic();
                        privateKeyHex = privateKeyEc.getPrivate('hex');
                        publicKey = this.getPublicKey();
                        publicKeyEc = publicKey.toElliptic();
                        publicKeyHex = publicKeyEc.getPublic('hex');
                        derHex = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420" + privateKeyHex + "a144034200" + publicKeyHex;
                        derBinary = Buffer.from(derHex, 'hex').toString('binary');
                        pkcs8ArrayBuffer = (0, eosjs_numeric_1.stringToArray)(derBinary);
                        return [4 /*yield*/, crypto.subtle.importKey('pkcs8', pkcs8ArrayBuffer, {
                                name: 'ECDSA',
                                namedCurve: 'P-256'
                            }, extractable, ['sign'])];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    PrivateKey.prototype.toLegacyString = function () {
        return (0, eosjs_numeric_1.privateKeyToLegacyString)(this.key);
    };
    /** Export private key as EOSIO-format private key */
    PrivateKey.prototype.toString = function () {
        return (0, eosjs_numeric_1.privateKeyToString)(this.key);
    };
    /** Get key type from key */
    PrivateKey.prototype.getType = function () {
        return this.key.type;
    };
    /** Retrieve the public key from a private key */
    PrivateKey.prototype.getPublicKey = function () {
        var ellipticPrivateKey = this.toElliptic();
        return PublicKey_1.PublicKey.fromElliptic(ellipticPrivateKey, this.getType(), this.ec);
    };
    /** Sign a message or hashed message digest with private key */
    PrivateKey.prototype.sign = function (data, shouldHash, encoding) {
        var _this = this;
        if (shouldHash === void 0) { shouldHash = true; }
        if (encoding === void 0) { encoding = 'utf8'; }
        if (shouldHash) {
            if (typeof data === 'string') {
                data = Buffer.from(data, encoding);
            }
            data = this.ec.hash().update(data).digest();
        }
        var tries = 0;
        var signature;
        var isCanonical = function (sigData) {
            return !(sigData[1] & 0x80) && !(sigData[1] === 0 && !(sigData[2] & 0x80))
                && !(sigData[33] & 0x80) && !(sigData[33] === 0 && !(sigData[34] & 0x80));
        };
        var constructSignature = function (options) {
            var ellipticPrivateKey = _this.toElliptic();
            var ellipticSignature = ellipticPrivateKey.sign(data, options);
            return Signature_1.Signature.fromElliptic(ellipticSignature, _this.getType(), _this.ec);
        };
        if (this.key.type === eosjs_numeric_1.KeyType.k1) {
            do {
                signature = constructSignature({ canonical: true, pers: [++tries] });
            } while (!isCanonical(signature.toBinary()));
        }
        else {
            signature = constructSignature({ canonical: true });
        }
        return signature;
    };
    /** Use Web Crypto to sign data (that matches types) with private CryptoKey */
    PrivateKey.prototype.webCryptoSign = function (data) {
        return __awaiter(this, void 0, void 0, function () {
            var publicKey, privWebCrypto, webCryptoSig;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        publicKey = this.getPublicKey();
                        return [4 /*yield*/, this.toWebCrypto()];
                    case 1:
                        privWebCrypto = _a.sent();
                        return [4 /*yield*/, crypto.subtle.sign({
                                name: 'ECDSA',
                                hash: {
                                    name: 'SHA-256'
                                }
                            }, privWebCrypto, data)];
                    case 2:
                        webCryptoSig = _a.sent();
                        return [2 /*return*/, Signature_1.Signature.fromWebCrypto(data, webCryptoSig, publicKey)];
                }
            });
        });
    };
    /** Validate a private key */
    PrivateKey.prototype.isValid = function () {
        try {
            var ellipticPrivateKey = this.toElliptic();
            var validationObj = ellipticPrivateKey.validate();
            return validationObj.result;
        }
        catch (_a) {
            return false;
        }
    };
    return PrivateKey;
}());
exports.PrivateKey = PrivateKey;
//# sourceMappingURL=PrivateKey.js.map