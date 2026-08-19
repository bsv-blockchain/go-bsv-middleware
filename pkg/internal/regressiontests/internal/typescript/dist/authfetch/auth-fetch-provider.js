"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthFetchProvider = void 0;
const sdk_1 = require("@bsv/sdk");
const show_1 = require("../show/show");
const auth_fetch_adapter_1 = require("./auth-fetch-adapter");
const actors_constants_1 = require("../constants/actors_constants");
class AuthFetchProvider {
    constructor() {
        this.clients = {};
        this.show = new show_1.Show(true);
    }
    provide(options) {
        const privKeyHex = options?.privKeyHex || actors_constants_1.alicePrivKey;
        const clientId = options?.clientId || privKeyHex;
        if (!this.clients[clientId]) {
            this.show.that('new AuthFetch client', {
                clientId: clientId,
                privKeyHex: privKeyHex,
            });
            const priv = sdk_1.PrivateKey.fromHex(privKeyHex);
            const wallet = new sdk_1.CompletedProtoWallet(priv);
            const client = new sdk_1.AuthFetch(wallet);
            this.clients[clientId] = {
                privKeyHex: privKeyHex,
                authFetch: new auth_fetch_adapter_1.AuthFetchAdapter(this.show, client),
                wallet: wallet
            };
        }
        else {
            this.show.that('using AuthFetch client', {
                clientId: clientId,
                privKeyHex: privKeyHex,
            });
        }
        return this.clients[clientId].authFetch;
    }
    cleanUp(clientId) {
        if (this.clients[clientId]) {
            this.show.that('removing cached AuthFetch client', {
                clientId: clientId,
                privKeyHex: this.clients[clientId].privKeyHex,
            });
            delete this.clients[clientId];
        }
    }
}
exports.AuthFetchProvider = AuthFetchProvider;
