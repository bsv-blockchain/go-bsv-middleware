import {Server, ServerCredentials} from "@grpc/grpc-js";
import {AuthFetchHandler} from "./grpc-auth-fetch";
import {AuthFetchService} from "./gen/auth_fetch";

function main() {
    const server = new Server();
    const authFetchHandler = new AuthFetchHandler()

    server.addService(AuthFetchService, {
        // ts-proto uses camelCase method names for grpc-js services
        fetch: authFetchHandler.fetchHandler(),
        cleanUp: authFetchHandler.cleanUpHandler(),
    });

    const port = process.env.PORT ?? "50050";
    const host = process.env.HOST ?? "0.0.0.0";
    const bindAddr = `${host}:${port}`;

    server.bindAsync(bindAddr, ServerCredentials.createInsecure(), (err, boundPort) => {
        if (err) {
            console.error("Failed to bind gRPC server:", err);
            process.exit(1);
        }
        console.log(`gRPC server is running on ${host}:${boundPort}`);
        console.log("Service: typescript.AuthFetch | Method: Fetch(url, config, options) -> FetchResponse");
    });
}

main();
