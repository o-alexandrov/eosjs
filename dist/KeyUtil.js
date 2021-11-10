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
exports.generateWebCryptoKeyPair = exports.generateKeyPair = void 0;
var elliptic_1 = require("elliptic");
var eosjs_numeric_1 = require("./eosjs-numeric");
var PublicKey_1 = require("./PublicKey");
var PrivateKey_1 = require("./PrivateKey");
var crypto = (typeof (window) !== 'undefined' ? window.crypto : require('crypto').webcrypto);
var generateKeyPair = function (type, options) {
    if (options === void 0) { options = {}; }
    if (!options.secureEnv) {
        throw new Error('Key generation is completely INSECURE in production environments in the browser. ' +
            'If you are absolutely certain this does NOT describe your environment, set `secureEnv` in your ' +
            'options to `true`.  If this does describe your environment and you set `secureEnv` to `true`, ' +
            'YOU DO SO AT YOUR OWN RISK AND THE RISK OF YOUR USERS.');
    }
    var ec;
    if (type === eosjs_numeric_1.KeyType.k1) {
        ec = new elliptic_1.ec('secp256k1');
    }
    else {
        ec = new elliptic_1.ec('p256');
    }
    var ellipticKeyPair = ec.genKeyPair(options.ecOptions);
    var publicKey = PublicKey_1.PublicKey.fromElliptic(ellipticKeyPair, type, ec);
    var privateKey = PrivateKey_1.PrivateKey.fromElliptic(ellipticKeyPair, type, ec);
    return { publicKey: publicKey, privateKey: privateKey };
};
exports.generateKeyPair = generateKeyPair;
/** Construct a p256/secp256r1 CryptoKeyPair from Web Crypto
 * Note: While creating a key that is not extractable means that it would not be possible
 * to convert the private key to string, it is not necessary to have the key extractable
 * for the Web Crypto Signature Provider.  Additionally, creating a key that is extractable
 * introduces security concerns.  For this reason, this function only creates CryptoKeyPairs
 * where the private key is not extractable and the public key is extractable.
 */
var generateWebCryptoKeyPair = function (keyUsage) {
    if (keyUsage === void 0) { keyUsage = ['sign', 'verify']; }
    return __awaiter(void 0, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, crypto.subtle.generateKey({
                        name: 'ECDSA',
                        namedCurve: 'P-256'
                    }, false, keyUsage)];
                case 1: return [2 /*return*/, _a.sent()];
            }
        });
    });
};
exports.generateWebCryptoKeyPair = generateWebCryptoKeyPair;
//# sourceMappingURL=KeyUtil.js.map