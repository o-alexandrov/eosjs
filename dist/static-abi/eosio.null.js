"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.abi = exports.value = exports.accountName = void 0;
exports.accountName = "eosio.null";
exports.value = {
    rawAbi: new Uint8Array(),
    abi: {
        version: "eosio::abi/1.0",
        types: [],
        structs: [
            {
                name: "nonce",
                base: "",
                fields: [{ name: "value", type: "string" }],
            },
        ],
        actions: [
            {
                name: "nonce",
                type: "nonce",
                ricardian_contract: "",
            },
        ],
        tables: [],
        ricardian_clauses: [],
        abi_extensions: [],
        error_messages: [],
    },
};
exports.abi = [exports.accountName, exports.value];
//# sourceMappingURL=eosio.null.js.map