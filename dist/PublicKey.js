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
exports.PublicKey = void 0;
var elliptic_1 = require("elliptic");
var eosjs_numeric_1 = require("./eosjs-numeric");
var crypto = (typeof (window) !== 'undefined' ? window.crypto : require('crypto').webcrypto);
/** Represents/stores a public key and provides easy conversion for use with `elliptic` lib */
var PublicKey = /** @class */ (function () {
    function PublicKey(key, ec) {
        this.key = key;
        this.ec = ec;
    }
    /** Instantiate public key from an EOSIO-format public key */
    PublicKey.fromString = function (publicKeyStr, ec) {
        var key = (0, eosjs_numeric_1.stringToPublicKey)(publicKeyStr);
        if (!ec) {
            if (key.type === eosjs_numeric_1.KeyType.k1) {
                ec = new elliptic_1.ec('secp256k1');
            }
            else {
                ec = new elliptic_1.ec('p256');
            }
        }
        return new PublicKey(key, ec);
    };
    /** Instantiate public key from an `elliptic`-format public key */
    PublicKey.fromElliptic = function (publicKey, keyType, ec) {
        var x = publicKey.getPublic().getX().toArray('be', 32);
        var y = publicKey.getPublic().getY().toArray('be', 32);
        if (!ec) {
            if (keyType === eosjs_numeric_1.KeyType.k1) {
                ec = new elliptic_1.ec('secp256k1');
            }
            else {
                ec = new elliptic_1.ec('p256');
            }
        }
        return new PublicKey({
            type: keyType,
            data: new Uint8Array([(y[31] & 1) ? 3 : 2].concat(x)),
        }, ec);
    };
    /** Instantiate public key from a `CryptoKey`-format public key */
    PublicKey.fromWebCrypto = function (publicKey) {
        return __awaiter(this, void 0, void 0, function () {
            var ec, extractedArrayBuffer, extractedDecoded, derHex, publicKeyHex, publicKeyEc;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (publicKey.extractable === false) {
                            throw new Error('Crypto Key is not extractable');
                        }
                        ec = new elliptic_1.ec('p256');
                        return [4 /*yield*/, crypto.subtle.exportKey('spki', publicKey)];
                    case 1:
                        extractedArrayBuffer = _a.sent();
                        extractedDecoded = (0, eosjs_numeric_1.arrayToString)(extractedArrayBuffer);
                        derHex = Buffer.from(extractedDecoded, 'binary').toString('hex');
                        publicKeyHex = derHex.replace('3059301306072a8648ce3d020106082a8648ce3d030107034200', '');
                        publicKeyEc = ec.keyFromPublic(publicKeyHex, 'hex');
                        return [2 /*return*/, PublicKey.fromElliptic(publicKeyEc, eosjs_numeric_1.KeyType.r1, ec)];
                }
            });
        });
    };
    /** Export public key as EOSIO-format public key */
    PublicKey.prototype.toString = function () {
        return (0, eosjs_numeric_1.publicKeyToString)(this.key);
    };
    /** Export public key as Legacy EOSIO-format public key */
    PublicKey.prototype.toLegacyString = function () {
        return (0, eosjs_numeric_1.publicKeyToLegacyString)(this.key);
    };
    /** Export public key as `elliptic`-format public key */
    PublicKey.prototype.toElliptic = function () {
        return this.ec.keyPair({
            pub: Buffer.from(this.key.data),
        });
    };
    /** Export public key as `CryptoKey`-format public key */
    PublicKey.prototype.toWebCrypto = function (extractable) {
        if (extractable === void 0) { extractable = false; }
        return __awaiter(this, void 0, void 0, function () {
            var publicKeyEc, publicKeyHex, derHex, derBase64, spkiArrayBuffer;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        publicKeyEc = this.toElliptic();
                        publicKeyHex = publicKeyEc.getPublic('hex');
                        derHex = "3059301306072a8648ce3d020106082a8648ce3d030107034200" + publicKeyHex;
                        derBase64 = Buffer.from(derHex, 'hex').toString('binary');
                        spkiArrayBuffer = (0, eosjs_numeric_1.stringToArray)(derBase64);
                        return [4 /*yield*/, crypto.subtle.importKey('spki', spkiArrayBuffer, {
                                name: 'ECDSA',
                                namedCurve: 'P-256'
                            }, extractable, ['verify'])];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /** Get key type from key */
    PublicKey.prototype.getType = function () {
        return this.key.type;
    };
    /** Validate a public key */
    PublicKey.prototype.isValid = function () {
        try {
            var ellipticPublicKey = this.toElliptic();
            var validationObj = ellipticPublicKey.validate();
            return validationObj.result;
        }
        catch (_a) {
            return false;
        }
    };
    return PublicKey;
}());
exports.PublicKey = PublicKey;
//# sourceMappingURL=PublicKey.js.map