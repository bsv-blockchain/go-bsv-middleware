import type {sendUnaryData, ServerUnaryCall} from "@grpc/grpc-js";
import {HandleCall} from "@grpc/grpc-js/build/src/server-call";

export class GrpcHandler<Request = any, Response = any> {
    private handleAsync: OmitThisParameter<(call: ServerUnaryCall<Request, Response>) => Promise<Response>>;

    constructor(handler: unknown, method: (call: ServerUnaryCall<Request, Response>) => Promise<Response>) {
        this.handleAsync = method.bind(handler)
    }

    handler(): HandleCall<Request, Response> {
        return (call: ServerUnaryCall<Request, Response>, callback: sendUnaryData<Response>): void => {
            this.handle(call, callback)
        }
    }

    handle(call: ServerUnaryCall<Request, Response>, callback: sendUnaryData<Response>): void {
        this.handleAsync(call)
            .then((resp) => callback(null, resp))
            .catch((err) => {
                if (err instanceof Error) {
                    callback(err as Error, null as unknown as Response)
                } else {
                    callback(new Error(JSON.stringify(err)), null as unknown as Response)
                }
            })
    }
}
