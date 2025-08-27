import type {ServerUnaryCall} from "@grpc/grpc-js";
import type {CleanUpRequest, CleanUpResponse, FetchRequest, FetchResponse} from "./gen/auth_fetch";
import {AuthFetchProvider} from "./authfetch/auth-fetch-provider";
import {GrpcHandler} from "./grpc-handler";
import {HandleCall} from "@grpc/grpc-js/build/src/server-call";
import {Show} from "./show/show";

export class AuthFetchHandler {
    show: Show = new Show(true);
    provider: AuthFetchProvider = new AuthFetchProvider()

    fetchHandler(): HandleCall<FetchRequest, FetchResponse> {
        return new GrpcHandler(this, this.fetch).handler()
    }

    cleanUpHandler(): HandleCall<CleanUpRequest, CleanUpResponse> {
        return new GrpcHandler(this, this.cleanUp).handler()
    }

    async fetch(call: ServerUnaryCall<FetchRequest, FetchResponse>): Promise<FetchResponse> {
        const {url, config, options} = call.request

        this.show.message("preparing auth fetch to make a request to ", url, " with config ", config, " and options ", options, "")

        const authFetch = this.provider.provide(options)

        return await authFetch.fetch({url, config})
    }

    async cleanUp(call: ServerUnaryCall<CleanUpRequest, CleanUpResponse>): Promise<CleanUpResponse> {
        this.provider.cleanUp(call.request.clientId)
        return {}
    }


}
