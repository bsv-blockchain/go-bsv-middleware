import {ChannelCredentials} from "@grpc/grpc-js";
import {AuthFetchClient, type FetchRequest, type FetchResponse} from "../gen/auth_fetch";
import {prepareOptions} from "./args";
import {printHelp} from "./help";


async function main() {
    const options = prepareOptions()

    if (options.help) {
        printHelp();
        process.exit(0);
    }


    const client = new AuthFetchClient(options.grpcAddress, ChannelCredentials.createInsecure());

    const req: FetchRequest = {
        url: options.url,
        config: options.config,
        options: options.options,
    };

    await new Promise<void>((resolve) => setTimeout(resolve, 10)); // slight delay to ensure channel creation

    const resp = await new Promise<FetchResponse>((resolve, reject) => {
        client.fetch(req, (err, resp: FetchResponse | undefined) => {
            if (err) {
                reject(err)
                return
            }
            if (resp) {
                resolve(resp)
                return
            }
            reject(new Error("No response received"))
        });
    })

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
