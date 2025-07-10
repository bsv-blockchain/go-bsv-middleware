import { prepareOptions } from './args';
import { AuthFetch, CompletedProtoWallet } from '@bsv/sdk';

export async function authFetch() {
  const { show, privKey, url, config } = prepareOptions();

  const wallet = new CompletedProtoWallet(privKey);

  const httpClient = new AuthFetch(wallet);

  try {
    const response = await httpClient.fetch(url, config);
    const body = await response.text();

    show.that('Fetch Result', 'REQUEST:', { url, ...config }, 'RESPONSE:', {
      ...response,
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
      body: body,
    };
  } catch (error) {
    show.that('Error on making fetch', 'REQUEST:', { url, ...config }, 'ERROR:', error);
    throw error;
  }
}
