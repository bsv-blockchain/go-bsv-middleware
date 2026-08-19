"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const grpc_js_1 = require("@grpc/grpc-js");
const auth_fetch_1 = require("../gen/auth_fetch");
const args_1 = require("./args");
const help_1 = require("./help");
// NOTICE: this client is not a part of the regression test mechanism,
// it is used for development purposes, to check the grpc functionality,
// It was used to confirm that the server was working correctly, but the Go client has some issue.
// That's why it stays in the repo.
async function main() {
    const options = (0, args_1.prepareOptions)();
    if (options.help) {
        (0, help_1.printHelp)();
        process.exit(0);
    }
    const client = new auth_fetch_1.AuthFetchClient(options.grpcAddress, grpc_js_1.ChannelCredentials.createInsecure());
    const req = {
        url: options.url,
        config: options.config,
        options: options.options,
    };
    await new Promise((resolve) => setTimeout(resolve, 10)); // slight delay to ensure channel creation
    const resp = await new Promise((resolve, reject) => {
        client.fetch(req, (err, resp) => {
            if (err) {
                reject(err);
                return;
            }
            if (resp) {
                resolve(resp);
                return;
            }
            reject(new Error("No response received"));
        });
    });
    // Pretty print response
    console.log("=== FetchResponse ===");
    console.log("status:", resp.status);
    console.log("statusText:", resp.statusText);
    console.log("headers:");
    for (const [k, v] of Object.entries(resp.headers || {})) {
        console.log(`  ${k}: ${v}`);
    }
    console.log("body:");
    console.log(resp.body || "");
    console.log("=====================");
    process.exit(0);
}
main().catch((e) => {
    console.error("Client fatal error:", e);
    process.exit(1);
});
