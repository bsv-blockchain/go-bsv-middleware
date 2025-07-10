// @ts-ignore
import minimist from 'minimist';
import process from 'node:process';
import { PrivateKey } from '@bsv/sdk';
import { createDebugHandler, Show } from '../show/show';

export interface SimplifiedFetchRequestOptions {
  method?: HTTPMethod;
  headers?: Record<string, string>;
  body?: any;
}

export interface Options {
  show: Show;
  privKey: PrivateKey;
  url: string;
  config: SimplifiedFetchRequestOptions;
}

type HTTPMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';

const defaultWIF = 'L268WKbTbLTrZL6aW5A5rzd4rLsZWWf7Gq3edRSFqGrCgarkYfJf';

function preparePrivKey() {
  const privKeyWif = process.env.REGRESSION_TEST_CLIENT_PRIVKEY_WIF || defaultWIF;
  return PrivateKey.fromWif(privKeyWif);
}

export function prepareOptions(): Options {
  const args = process.argv.slice(2);
  const parsedArgs = minimist(args);

  const result: Options = {
    show: createDebugHandler(parsedArgs),
    privKey: preparePrivKey(),
    url: extractURL(parsedArgs),
    config: {
      method: extractMethod(parsedArgs),
      body: extractBody(parsedArgs),
      headers: extractHeaders(parsedArgs),
    },
  };

  result.show.that('Parsed options', {
    ...result,
    show: result.show.debug,
    privKey: result.privKey.toWif(),
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

  if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].includes(method)) {
    throw new Error(`Invalid HTTP method: ${parsedArgs.method}`);
  }

  return method;
}

function extractBody(parsedArgs: minimist.ParsedArgs) {
  if (!parsedArgs.body) {
    return undefined;
  }

  try {
    return JSON.parse(parsedArgs.body);
  } catch (error) {
    throw new Error(`Invalid JSON body: ${parsedArgs.body}`);
  }
}

function extractHeaders(parsedArgs: minimist.ParsedArgs) {
  if (!parsedArgs.header) {
    return undefined;
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
