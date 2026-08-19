"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.prepareOptions = prepareOptions;
// @ts-ignore
const minimist_1 = __importDefault(require("minimist"));
const node_process_1 = __importDefault(require("node:process"));
const show_1 = require("../show/show");
const actors_constants_1 = require("../constants/actors_constants");
const node_crypto_1 = require("node:crypto");
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
function prepareOptions() {
    const args = node_process_1.default.argv.slice(2);
    const parsedArgs = (0, minimist_1.default)(args);
    const result = {
        help: !!parsedArgs.help || !!parsedArgs.h,
        show: new show_1.Show(true),
        url: extractURL(parsedArgs),
        grpcAddress: parsedArgs.addr || node_process_1.default.env.GRPC_ADDR || "localhost:50050",
        config: {
            method: extractMethod(parsedArgs),
            body: extractBody(parsedArgs),
            headers: extractHeaders(parsedArgs),
            retryCounter: parsedArgs.retryCounter ? Number(parsedArgs.retryCounter) : 1,
        },
        options: {
            privKeyHex: actors_constants_1.alicePrivKey,
            clientId: parsedArgs.fresh ? (0, node_crypto_1.randomUUID)().toString() : actors_constants_1.alicePrivKey,
        }
    };
    result.show.that('Parsed program arguments:', {
        ...result,
        show: result.show.debug,
    });
    return result;
}
function extractURL(parsedArgs) {
    if (!parsedArgs.url) {
        throw new Error('URL is required');
    }
    if (typeof parsedArgs.url !== 'string') {
        throw new Error('URL must be a string');
    }
    try {
        new URL(parsedArgs.url);
    }
    catch (error) {
        throw new Error(`Invalid URL: ${parsedArgs.url}`);
    }
    return parsedArgs.url;
}
function extractMethod(parsedArgs) {
    if (!parsedArgs.method) {
        return 'GET';
    }
    if (typeof parsedArgs.method !== 'string') {
        throw new Error('Method must be a string');
    }
    const method = parsedArgs.method.toUpperCase();
    if (!HTTP_METHODS.includes(method)) {
        throw new Error(`Invalid HTTP method: ${parsedArgs.method}`);
    }
    return method;
}
function extractBody(parsedArgs) {
    if (!parsedArgs.body) {
        return "";
    }
    return parsedArgs.body;
}
function extractHeaders(parsedArgs) {
    if (!parsedArgs.header) {
        return {};
    }
    const headersArgs = Array.isArray(parsedArgs.header) ? parsedArgs.header : [parsedArgs.header];
    const headers = headersArgs
        .map((it) => {
        if (typeof it !== 'string') {
            throw new Error(`Invalid header: ${it}. Expected string`);
        }
        return it;
    })
        .map((it) => {
        const parts = it.split(':');
        if (parts.length !== 2) {
            throw new Error(`Invalid header format: ${it}. Expected format: "name:value"`);
        }
        const name = parts[0].trim();
        const value = parts[1].trim();
        if (!name || !value) {
            throw new Error(`Invalid header: ${it}. Name and value cannot be empty`);
        }
        return [name, value];
    });
    return Object.fromEntries(headers);
}
