"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthFetchHandler = void 0;
const auth_fetch_provider_1 = require("./authfetch/auth-fetch-provider");
const grpc_handler_1 = require("./grpc-handler");
const show_1 = require("./show/show");
class AuthFetchHandler {
    constructor() {
        this.show = new show_1.Show(true);
        this.provider = new auth_fetch_provider_1.AuthFetchProvider();
    }
    fetchHandler() {
        return new grpc_handler_1.GrpcHandler(this, this.fetch).handler();
    }
    cleanUpHandler() {
        return new grpc_handler_1.GrpcHandler(this, this.cleanUp).handler();
    }
    async fetch(call) {
        const { url, config, options } = call.request;
        this.show.message("preparing auth fetch to make a request to ", url, " with config ", config, " and options ", options, "");
        const authFetch = this.provider.provide(options);
        return await authFetch.fetch({ url, config });
    }
    async cleanUp(call) {
        this.provider.cleanUp(call.request.clientId);
        return {};
    }
}
exports.AuthFetchHandler = AuthFetchHandler;
