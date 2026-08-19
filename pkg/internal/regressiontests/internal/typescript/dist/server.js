"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const grpc_js_1 = require("@grpc/grpc-js");
const grpc_auth_fetch_1 = require("./grpc-auth-fetch");
const auth_fetch_1 = require("./gen/auth_fetch");
function main() {
    const server = new grpc_js_1.Server();
    const authFetchHandler = new grpc_auth_fetch_1.AuthFetchHandler();
    server.addService(auth_fetch_1.AuthFetchService, {
        // ts-proto uses camelCase method names for grpc-js services
        fetch: authFetchHandler.fetchHandler(),
        cleanUp: authFetchHandler.cleanUpHandler(),
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
