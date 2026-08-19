"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthFetchAdapter = void 0;
class AuthFetchAdapter {
    constructor(show, authFetch) {
        this.show = show;
        this.authFetch = authFetch;
    }
    async fetch(req) {
        let url = this.extractUrl(req);
        const { config } = req;
        let { retryCounter } = config || {};
        if (!retryCounter) {
            retryCounter = 1;
        }
        try {
            const response = await this.authFetch.fetch(url, {
                method: config?.method || undefined,
                body: config?.body || undefined,
                headers: config?.headers || undefined,
                retryCounter
            });
            const body = await response.text();
            this.show.that('Fetch Result', 'REQUEST:', { url, ...config }, 'RESPONSE:', {
                url: response.url,
                status: response.status,
                statusText: response.statusText,
                type: response.type,
                headers: response.headers,
                body: body,
            });
            const headers = {};
            response.headers.forEach((value, key) => {
                headers[key] = value;
            });
            return {
                status: response.status,
                statusText: response.statusText,
                headers: headers,
                body: body
            };
        }
        catch (error) {
            this.show.that('Error on making fetch', 'REQUEST:', { url, ...config }, 'ERROR:', error);
            // translate error message in case of connection refused to more detailed one
            if (isConnectionRefusedError(error)) {
                try {
                    error = new Error(error.cause.errors.map(err => err.message).join(" & "));
                }
                catch (err) {
                    this.show.that('error when trying to provide more detailed error', err);
                }
            }
            throw error;
        }
    }
    extractUrl(req) {
        let { url } = req;
        if (!process.env.FETCH_LOCALHOST_REPLACEMENT) {
            return url;
        }
        const parsedUrl = URL.parse(url);
        if (!parsedUrl) {
            return url;
        }
        if (parsedUrl?.hostname === 'localhost' || parsedUrl?.hostname === '127.0.0.1') {
            parsedUrl.hostname = process.env.FETCH_LOCALHOST_REPLACEMENT;
            url = parsedUrl.toString();
            this.show.that('Calling from docker', `original url: ${req.url}`, `rewritten url: ${url}`);
        }
        return url;
    }
}
exports.AuthFetchAdapter = AuthFetchAdapter;
function isConnectionRefusedError(error) {
    return !!error && typeof error == 'object' &&
        'cause' in error && typeof error.cause === 'object' && !!error.cause &&
        'code' in error.cause && error.cause.code === 'ECONNREFUSED' &&
        'errors' in error.cause && Array.isArray(error.cause.errors) &&
        error.cause.errors.length > 0;
}
