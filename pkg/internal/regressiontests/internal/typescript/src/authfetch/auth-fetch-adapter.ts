import {AuthFetch} from "@bsv/sdk";
import {Config, FetchResponse} from "../gen/auth_fetch";
import {Show} from "../show/show";

export interface AuthFetchRequest {
    url: string;
    config?: Config;
}

export class AuthFetchAdapter {
    constructor(private show: Show, private authFetch: AuthFetch) {
    }

    async fetch(req: AuthFetchRequest): Promise<FetchResponse> {
        let url = this.extractUrl(req);

        const {config} = req;
        let {retryCounter} = config || {}
        if (!retryCounter) {
            retryCounter = 1
        }


        try {
            const response = await this.authFetch.fetch(
                url,
                {
                    method: config?.method || undefined,
                    body: config?.body || undefined,
                    headers: config?.headers || undefined,
                    retryCounter
                }
            )
            const body = await response.text();

            this.show.that('Fetch Result', 'REQUEST:', {url, ...config}, 'RESPONSE:', {
                url: response.url,
                status: response.status,
                statusText: response.statusText,
                type: response.type,
                headers: response.headers,
                body: body,
            });

            const headers: Record<string, string> = {};
            response.headers.forEach((value, key) => {
                headers[key] = value;
            });

            return {
                status: response.status,
                statusText: response.statusText,
                headers: headers,
                body: body
            } as FetchResponse;
        } catch (error) {
            this.show.that('Error on making fetch', 'REQUEST:', {url, ...config}, 'ERROR:', error);
            // translate error message in case of connection refused to more detailed one
            if (isConnectionRefusedError(error)) {
                try {
                    error = new Error(error.cause.errors.map(err => err.message).join(" & "))
                } catch (err) {
                    this.show.that('error when trying to provide more detailed error', err)
                }
            }

            throw error;
        }
    }

    private extractUrl(req: AuthFetchRequest) {
        let {url} = req;

        if (!process.env.FETCH_LOCALHOST_REPLACEMENT) {
            return url;
        }

        const parsedUrl = URL.parse(url)
        if (!parsedUrl) {
            return url
        }
        if (parsedUrl?.hostname === 'localhost' || parsedUrl?.hostname === '127.0.0.1') {
            parsedUrl.hostname = process.env.FETCH_LOCALHOST_REPLACEMENT
            url = parsedUrl.toString()
            this.show.that('Calling from docker', `original url: ${req.url}`, `rewritten url: ${url}`)
        }
        return url
    }
}

interface ConnectionRefusedError {
    cause: {
        code: "ECONNREFUSED",
        errors: Array<{ message: string }>
    }
}


function isConnectionRefusedError(error: unknown): error is ConnectionRefusedError {
    return !!error && typeof error == 'object' &&
        'cause' in error && typeof error.cause === 'object' && !!error.cause &&
        'code' in error.cause && error.cause.code === 'ECONNREFUSED' &&
        'errors' in error.cause && Array.isArray(error.cause.errors) &&
        error.cause.errors.length > 0
}
