"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256 = exports.generateWebCryptoKeyPair = exports.generateKeyPair = exports.Signature = exports.PublicKey = exports.PrivateKey = void 0;
var hash = require("hash.js");
var PrivateKey_1 = require("./PrivateKey");
Object.defineProperty(exports, "PrivateKey", { enumerable: true, get: function () { return PrivateKey_1.PrivateKey; } });
var PublicKey_1 = require("./PublicKey");
Object.defineProperty(exports, "PublicKey", { enumerable: true, get: function () { return PublicKey_1.PublicKey; } });
var Signature_1 = require("./Signature");
Object.defineProperty(exports, "Signature", { enumerable: true, get: function () { return Signature_1.Signature; } });
var KeyUtil_1 = require("./KeyUtil");
Object.defineProperty(exports, "generateKeyPair", { enumerable: true, get: function () { return KeyUtil_1.generateKeyPair; } });
Object.defineProperty(exports, "generateWebCryptoKeyPair", { enumerable: true, get: function () { return KeyUtil_1.generateWebCryptoKeyPair; } });
var sha256 = function (data) {
    return hash.sha256().update(data).digest();
};
exports.sha256 = sha256;
//# sourceMappingURL=eosjs-key-conversions.js.map