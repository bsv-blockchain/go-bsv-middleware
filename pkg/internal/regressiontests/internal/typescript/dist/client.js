"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const grpc_js_1 = require("@grpc/grpc-js");
const auth_fetch_1 = require("./gen/auth_fetch");
// Simple CLI argument parser (no extra deps). Supports:
// --addr host:port (default: localhost:50051)
// --url URL (required)
// --method METHOD (optional)
// --header "Key: Value" (can be repeated)
// --body STRING (optional)
// --retry N (optional)
// --fresh (optional, boolean)
// --timeout MS (optional)
// --metadata "Key: Value" (repeated, optional) for gRPC metadata
function parseArgs(argv) {
    const args = { headers: [], metadata: [] };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        const next = () => argv[++i];
        switch (a) {
            case "--addr":
                args.addr = next();
                break;
            case "--url":
                args.url = next();
                break;
            case "--method":
                args.method = next();
                break;
            case "--header":
                args.headers.push(next());
                break;
            case "--body":
                args.body = next();
                break;
            case "--retry":
                args.retry = Number(next());
                break;
            case "--fresh":
                args.fresh = true;
                break;
            case "--timeout":
                args.timeout = Number(next());
                break;
            case "--metadata":
                args.metadata.push(next());
                break;
            case "-h":
            case "--help":
                args.help = true;
                break;
            default:
                // ignore unknowns for minimalism
                break;
        }
    }
    return args;
}
function printHelp() {
    console.log(`Usage: node dist/client.js [options]

Options:
  --addr host:port        gRPC server address (default: localhost:50051)
  --url URL               Target URL to fetch (required)
  --method METHOD         HTTP method (default: GET)
  --header "K: V"         HTTP header (can be repeated)
  --body STRING           Request body string
  --retry N               Retry counter number
  --fresh                 Use fresh instance option (boolean)
  --timeout MS            gRPC deadline/timeout in milliseconds
  --metadata "K: V"       gRPC metadata entry (can be repeated)
  -h, --help              Show this help

Examples:
  npm run client -- --url https://example.com
  npm run client -- --addr localhost:50051 --url https://httpbin.org/anything --method POST --header "content-type: application/json" --body '{"hello":"world"}'
`);
}
function parseKeyValueList(items) {
    const out = {};
    for (const item of items) {
        if (!item)
            continue;
        const idx = item.indexOf(":");
        if (idx === -1)
            continue;
        const key = item.slice(0, idx).trim();
        const val = item.slice(idx + 1).trim();
        if (key)
            out[key.toLowerCase()] = val;
    }
    return out;
}
async function main() {
    const argv = process.argv.slice(2);
    const args = parseArgs(argv);
    if (args.help) {
        printHelp();
        process.exit(0);
    }
    const addr = args.addr || process.env.GRPC_ADDR || "localhost:50051";
    const url = args.url || process.env.FETCH_URL;
    if (!url) {
        console.error("Error: --url is required (or set FETCH_URL env var).\n");
        printHelp();
        process.exit(2);
    }
    const headers = parseKeyValueList(args.headers || []);
    const mdPairs = parseKeyValueList(args.metadata || []);
    const client = new auth_fetch_1.AuthFetchClient(addr, grpc_js_1.ChannelCredentials.createInsecure());
    const req = {
        url,
        config: {
            method: args.method || "GET",
            headers,
            body: args.body ?? "",
            retryCounter: Number.isFinite(args.retry) ? Number(args.retry) : 0,
        },
        options: {
            useFreshInstance: !!args.fresh,
        },
    };
    const metadata = new grpc_js_1.Metadata();
    for (const [k, v] of Object.entries(mdPairs)) {
        metadata.add(k, v);
    }
    const callOptions = args.timeout && Number.isFinite(args.timeout)
        ? { deadline: new Date(Date.now() + Number(args.timeout)) }
        : undefined;
    await new Promise((resolve) => setTimeout(resolve, 10)); // slight delay to ensure channel creation
    client.fetch(req, metadata, callOptions, (err, resp) => {
        if (err) {
            console.error("Fetch RPC error:", {
                code: err.code,
                details: err.details,
                message: err.message,
            });
            process.exitCode = 1;
            return;
        }
        if (!resp) {
            console.error("Fetch RPC returned empty response");
            process.exitCode = 1;
            return;
        }
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
    });
}
main().catch((e) => {
    console.error("Client fatal error:", e);
    process.exit(1);
});
