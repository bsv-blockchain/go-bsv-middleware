import {AuthFetch, CompletedProtoWallet, PrivateKey, WalletInterface} from "@bsv/sdk";
import {Options} from "../gen/auth_fetch";
import {Show} from "../show/show";
import {AuthFetchAdapter} from "./auth-fetch-adapter";
import {alicePrivKey} from "../constants/actors_constants";

interface Client {
    privKeyHex: string,
    authFetch: AuthFetchAdapter
    wallet: WalletInterface
}

export class AuthFetchProvider {
    clients: Record<string, Client> = {}
    show: Show = new Show(true);

    provide(options?: Options): AuthFetchAdapter {
        const privKeyHex = options?.privKeyHex || alicePrivKey
        const clientId = options?.clientId || privKeyHex

        if (!this.clients[clientId]) {
            this.show.that('new AuthFetch client', {
                clientId: clientId,
                privKeyHex: privKeyHex,
            })
            const priv = PrivateKey.fromHex(privKeyHex)
            const wallet = new CompletedProtoWallet(priv)
            const client = new AuthFetch(wallet);
            this.clients[clientId] = {
                privKeyHex: privKeyHex,
                authFetch: new AuthFetchAdapter(this.show, client),
                wallet: wallet
            }
        } else {
            this.show.that('using AuthFetch client', {
                clientId: clientId,
                privKeyHex: privKeyHex,
            })
        }

        return this.clients[clientId].authFetch
    }

    cleanUp(clientId: string) {
        if (this.clients[clientId]) {
            this.show.that('removing cached AuthFetch client', {
                clientId: clientId,
                privKeyHex: this.clients[clientId].privKeyHex,
            })
            delete this.clients[clientId]
        }
    }
}
