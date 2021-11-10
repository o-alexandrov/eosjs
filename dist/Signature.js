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
exports.Signature = void 0;
var elliptic_1 = require("elliptic");
var BN = require("bn.js");
var eosjs_numeric_1 = require("./eosjs-numeric");
var PublicKey_1 = require("./PublicKey");
var crypto = (typeof (window) !== 'undefined' ? window.crypto : require('crypto').webcrypto);
/** Represents/stores a Signature and provides easy conversion for use with `elliptic` lib */
var Signature = /** @class */ (function () {
    function Signature(signature, ec) {
        this.signature = signature;
        this.ec = ec;
    }
    /** Instantiate Signature from an EOSIO-format Signature */
    Signature.fromString = function (sig, ec) {
        var signature = (0, eosjs_numeric_1.stringToSignature)(sig);
        if (!ec) {
            if (signature.type === eosjs_numeric_1.KeyType.k1) {
                ec = new elliptic_1.ec('secp256k1');
            }
            else {
                ec = new elliptic_1.ec('p256');
            }
        }
        return new Signature(signature, ec);
    };
    /** Instantiate Signature from an `elliptic`-format Signature */
    Signature.fromElliptic = function (ellipticSig, keyType, ec) {
        var r = ellipticSig.r.toArray('be', 32);
        var s = ellipticSig.s.toArray('be', 32);
        var eosioRecoveryParam;
        if (keyType === eosjs_numeric_1.KeyType.k1 || keyType === eosjs_numeric_1.KeyType.r1) {
            eosioRecoveryParam = ellipticSig.recoveryParam + 27;
            if (ellipticSig.recoveryParam <= 3) {
                eosioRecoveryParam += 4;
            }
        }
        else if (keyType === eosjs_numeric_1.KeyType.wa) {
            eosioRecoveryParam = ellipticSig.recoveryParam;
        }
        var sigData = new Uint8Array([eosioRecoveryParam].concat(r, s));
        if (!ec) {
            if (keyType === eosjs_numeric_1.KeyType.k1) {
                ec = new elliptic_1.ec('secp256k1');
            }
            else {
                ec = new elliptic_1.ec('p256');
            }
        }
        return new Signature({
            type: keyType,
            data: sigData,
        }, ec);
    };
    /** Instantiate Signature from a Web Crypto Signature */
    Signature.fromWebCrypto = function (data, webCryptoSig, publicKey) {
        return __awaiter(this, void 0, void 0, function () {
            var ec, hash, r, s, halforder, recoveryParam;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        ec = new elliptic_1.ec('p256');
                        return [4 /*yield*/, crypto.subtle.digest('SHA-256', data)];
                    case 1:
                        hash = _a.sent();
                        r = new BN(new Uint8Array(webCryptoSig.slice(0, 32)), 32);
                        s = new BN(new Uint8Array(webCryptoSig.slice(32)), 32);
                        halforder = ec.curve.n.ushrn(1);
                        if (s.ucmp(halforder) === 1) {
                            s = ec.curve.n.sub(s);
                        }
                        recoveryParam = this.getRecoveryParam(Buffer.from(hash), { r: r, s: s }, publicKey.toString(), ec);
                        return [2 /*return*/, Signature.fromElliptic({ r: r, s: s, recoveryParam: recoveryParam }, eosjs_numeric_1.KeyType.r1, ec)];
                }
            });
        });
    };
    /** Export Signature as `elliptic`-format Signature
     * NOTE: This isn't an actual elliptic-format Signature, as ec.Signature is not exported by the library.
     * That's also why the return type is `any`.  We're *actually* returning an object with the 3 params
     * not an ec.Signature.
     * Further NOTE: @types/elliptic shows ec.Signature as exported; it is *not*.  Hence the `any`.
     */
    Signature.prototype.toElliptic = function () {
        var lengthOfR = 32;
        var lengthOfS = 32;
        var r = new BN(this.signature.data.slice(1, lengthOfR + 1));
        var s = new BN(this.signature.data.slice(lengthOfR + 1, lengthOfR + lengthOfS + 1));
        var ellipticRecoveryBitField;
        if (this.signature.type === eosjs_numeric_1.KeyType.k1 || this.signature.type === eosjs_numeric_1.KeyType.r1) {
            ellipticRecoveryBitField = this.signature.data[0] - 27;
            if (ellipticRecoveryBitField > 3) {
                ellipticRecoveryBitField -= 4;
            }
        }
        else if (this.signature.type === eosjs_numeric_1.KeyType.wa) {
            ellipticRecoveryBitField = this.signature.data[0];
        }
        var recoveryParam = ellipticRecoveryBitField & 3;
        return { r: r, s: s, recoveryParam: recoveryParam };
    };
    /** Export Signature as EOSIO-format Signature */
    Signature.prototype.toString = function () {
        return (0, eosjs_numeric_1.signatureToString)(this.signature);
    };
    /** Export Signature in binary format */
    Signature.prototype.toBinary = function () {
        return this.signature.data;
    };
    /** Get key type from signature */
    Signature.prototype.getType = function () {
        return this.signature.type;
    };
    /** Verify a signature with a message or hashed message digest and public key */
    Signature.prototype.verify = function (data, publicKey, shouldHash, encoding) {
        if (shouldHash === void 0) { shouldHash = true; }
        if (encoding === void 0) { encoding = 'utf8'; }
        if (shouldHash) {
            if (typeof data === 'string') {
                data = Buffer.from(data, encoding);
            }
            data = this.ec.hash().update(data).digest();
        }
        var ellipticSignature = this.toElliptic();
        var ellipticPublicKey = publicKey.toElliptic();
        return this.ec.verify(data, ellipticSignature, ellipticPublicKey, encoding);
    };
    /** Verify a Web Crypto signature with data (that matches types) and public key */
    Signature.prototype.webCryptoVerify = function (data, webCryptoSig, publicKey) {
        return __awaiter(this, void 0, void 0, function () {
            var webCryptoPub;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, publicKey.toWebCrypto()];
                    case 1:
                        webCryptoPub = _a.sent();
                        return [4 /*yield*/, crypto.subtle.verify({
                                name: 'ECDSA',
                                hash: {
                                    name: 'SHA-256'
                                }
                            }, webCryptoPub, webCryptoSig, data)];
                    case 2: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /** Recover a public key from a message or hashed message digest and signature */
    Signature.prototype.recover = function (data, shouldHash, encoding) {
        if (shouldHash === void 0) { shouldHash = true; }
        if (encoding === void 0) { encoding = 'utf8'; }
        if (shouldHash) {
            if (typeof data === 'string') {
                data = Buffer.from(data, encoding);
            }
            data = this.ec.hash().update(data).digest();
        }
        var ellipticSignature = this.toElliptic();
        var recoveredPublicKey = this.ec.recoverPubKey(data, ellipticSignature, ellipticSignature.recoveryParam, encoding);
        var ellipticKPub = this.ec.keyFromPublic(recoveredPublicKey);
        return PublicKey_1.PublicKey.fromElliptic(ellipticKPub, this.getType(), this.ec);
    };
    /** Replaced version of getRecoveryParam from `elliptic` library */
    Signature.getRecoveryParam = function (digest, signature, publicKey, ec) {
        var recoveredKey;
        for (var i = 0; i < 4; i++) {
            try {
                var keyPair = ec.recoverPubKey(digest, signature, i);
                recoveredKey = PublicKey_1.PublicKey.fromElliptic(ec.keyFromPublic(keyPair), eosjs_numeric_1.KeyType.r1, ec).toString();
            }
            catch (e) {
                continue;
            }
            if (recoveredKey === publicKey) {
                return i;
            }
        }
        throw new Error('Unable to find valid recovery factor');
    };
    return Signature;
}());
exports.Signature = Signature;
//# sourceMappingURL=Signature.js.map