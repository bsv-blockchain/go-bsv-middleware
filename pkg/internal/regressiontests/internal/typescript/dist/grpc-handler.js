"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GrpcHandler = void 0;
class GrpcHandler {
    constructor(handler, method) {
        this.handleAsync = method.bind(handler);
    }
    handler() {
        return (call, callback) => {
            this.handle(call, callback);
        };
    }
    handle(call, callback) {
        this.handleAsync(call)
            .then((resp) => callback(null, resp))
            .catch((err) => {
            if (err instanceof Error) {
                callback(err, null);
            }
            else {
                callback(new Error(JSON.stringify(err)), null);
            }
        });
    }
}
exports.GrpcHandler = GrpcHandler;
