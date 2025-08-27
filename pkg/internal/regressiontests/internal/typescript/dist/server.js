"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const grpc_js_1 = require("@grpc/grpc-js");
const authFetch_1 = require("./authFetch");
const auth_fetch_1 = require("./gen/auth_fetch");
function main() {
    const server = new grpc_js_1.Server();
    server.addService(auth_fetch_1.AuthFetchService, {
        // ts-proto uses camelCase method names for grpc-js services
        fetch: authFetch_1.fetchHandler,
    });
    const port = process.env.PORT ?? "50050";
    const host = process.env.HOST ?? "0.0.0.0";
    const bindAddr = `${host}:${port}`;
    server.bindAsync(bindAddr, grpc_js_1.ServerCredentials.createInsecure(), (err, boundPort) => {
        if (err) {
            console.error("Failed to bind gRPC server:", err);
            process.exit(1);
        }
        console.log(`gRPC server is running on ${host}:${boundPort}`);
        console.log("Service: typescript.AuthFetch | Method: Fetch(url, config, options) -> FetchResponse");
    });
}
main();
