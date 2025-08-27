"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fetchHandlerAsync = fetchHandlerAsync;
exports.fetchHandler = fetchHandler;
// The async implementation of the Fetch handler
async function fetchHandlerAsync(req) {
    // TODO: implement fetch
    // Here you should implement the actual HTTP(S) fetch logic respecting:
    // - req.url (string)
    // - req.config?.method (string, optional)
    // - req.config?.headers (map<string,string>, optional)
    // - req.config?.body (string, optional; you can decide how to serialize/deserialize it)
    // - req.config?.retryCounter (number, optional)
    // - req.options?.useFreshInstance (boolean, optional)
    // The function must return an object of shape FetchResponse.
    // Placeholder response to indicate unimplemented logic.
    return {
        status: 501,
        statusText: "Not Implemented",
        headers: { "content-type": "text/plain" },
        body: "fetch is not implemented yet",
    };
}
// Bridge function for gRPC callback style (grpc-js expects callback-style handlers)
function fetchHandler(call, callback) {
    // call.request is already a typed FetchRequest from ts-proto
    fetchHandlerAsync(call.request)
        .then((resp) => callback(null, resp))
        .catch((err) => callback(err, null));
}
