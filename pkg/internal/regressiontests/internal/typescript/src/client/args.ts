// @ts-ignore
import minimist from 'minimist';
import process from 'node:process';
import {Show} from '../show/show';
import {Config, Options} from "../gen/auth_fetch";
import {alicePrivKey} from "../constants/actors_constants";
import {randomUUID} from "node:crypto";

export interface ProgramOptions {
    show: Show;
    help: boolean;
    grpcAddress: string;
    url: string;
    config: Config;
    options: Options
}


const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
type HTTPMethod = (typeof HTTP_METHODS)[number];

export function prepareOptions(): ProgramOptions {
    const args = process.argv.slice(2);
    const parsedArgs = minimist(args);

    const result: ProgramOptions = {
        help: !!parsedArgs.help || !!parsedArgs.h,
        show: new Show(true),
        url: extractURL(parsedArgs),
        grpcAddress: parsedArgs.addr || process.env.GRPC_ADDR || "localhost:50050",
        config: {
            method: extractMethod(parsedArgs),
            body: extractBody(parsedArgs),
            headers: extractHeaders(parsedArgs),
            retryCounter: parsedArgs.retryCounter ? Number(parsedArgs.retryCounter) : 1,
        },
        options: {
            privKeyHex: alicePrivKey,
            clientId: parsedArgs.fresh ? randomUUID().toString() : alicePrivKey,
        }
    };

    result.show.that('Parsed program arguments:', {
        ...result,
        show: result.show.debug,
    });

    return result;
}

function extractURL(parsedArgs: minimist.ParsedArgs): string {
    if (!parsedArgs.url) {
        throw new Error('URL is required');
    }

    if (typeof parsedArgs.url !== 'string') {
        throw new Error('URL must be a string');
    }

    try {
        new URL(parsedArgs.url);
    } catch (error) {
        throw new Error(`Invalid URL: ${parsedArgs.url}`);
    }

    return parsedArgs.url;
}

function extractMethod(parsedArgs: minimist.ParsedArgs): HTTPMethod {
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

function extractBody(parsedArgs: minimist.ParsedArgs) {
    if (!parsedArgs.body) {
        return "";
    }
    return parsedArgs.body;
}

function extractHeaders(parsedArgs: minimist.ParsedArgs): { [key: string]: string } {
    if (!parsedArgs.header) {
        return {};
    }

    const headersArgs = Array.isArray(parsedArgs.header) ? parsedArgs.header : [parsedArgs.header];

    const headers = headersArgs
        .map((it: unknown) => {
            if (typeof it !== 'string') {
                throw new Error(`Invalid header: ${it}. Expected string`);
            }
            return it as string;
        })
        .map((it: string) => {
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
