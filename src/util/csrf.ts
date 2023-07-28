import { createHash, createHmac, randomInt } from 'crypto';

export interface CSRFTokens {
  nonce?: string;
  nonceHmac?: string;
  pkce?: string;
  pkceHash?: string;
  state?: string;
}

export const NONCE_COOKIE_NAME_SUFFIX: keyof CSRFTokens = 'nonce';
export const NONCE_HMAC_COOKIE_NAME_SUFFIX: keyof CSRFTokens = 'nonceHmac';
export const PKCE_COOKIE_NAME_SUFFIX: keyof CSRFTokens = 'pkce';

export const CSRF_CONFIG = {
  secretAllowedCharacters:
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~',
  pkceLength: 43, // Should be between 43 and 128 - per spec
  nonceLength: 16,
  nonceMaxAge: 60 * 60 * 24,
};

export function generateNonce() {
  const randomString = generateSecret(
    CSRF_CONFIG.secretAllowedCharacters,
    CSRF_CONFIG.nonceLength
  );
  return `${getCurrentTimestampInSeconds()}T${randomString}`;
}

export function generateCSRFTokens(redirectURI: string, signingSecret: string) {
  const nonce = generateNonce();
  const nonceHmac = signNonce(nonce, signingSecret);

  const state = urlSafe.stringify(
    Buffer.from(
      JSON.stringify({
        nonce,
        redirect_uri: redirectURI,
      })
    ).toString('base64')
  );

  return {
    nonce,
    nonceHmac,
    state,
    ...generatePkceVerifier(),
  };
}

export function getCurrentTimestampInSeconds(): number {
  return (Date.now() / 1000) || 0;
}

export function generateSecret(allowedCharacters: string, secretLength: number) {
  return [...new Array(secretLength)]
    .map(() => allowedCharacters[randomInt(0, allowedCharacters.length)])
    .join('');
}

export function sign(stringToSign: string, secret: string, signatureLength: number): string {
  const digest = createHmac('sha256', secret)
    .update(stringToSign)
    .digest('base64')
    .slice(0, signatureLength);
  const signature = urlSafe.stringify(digest);
  return signature;
}

export function signNonce(nonce: string, signingSecret: string): string {
  return sign(nonce, signingSecret, CSRF_CONFIG.nonceLength);
}

export const urlSafe = {
  /*
  Functions to translate base64-encoded strings, so they can be used:
  - in URL's without needing additional encoding
  - in OAuth2 PKCE verifier
  - in cookies (to be on the safe side, as = + / are in fact valid characters in cookies)

  stringify:
      use this on a base64-encoded string to translate = + / into replacement characters

  parse:
      use this on a string that was previously urlSafe.stringify'ed to return it to
      its prior pure-base64 form. Note that trailing = are not added, but NodeJS does not care
    */
  stringify: (b64encodedString: string) =>
    b64encodedString.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
  parse: (b64encodedString: string) =>
    b64encodedString.replace(/-/g, '+').replace(/_/g, '/'),
};

export function generatePkceVerifier() {
  const pkce = generateSecret(
    CSRF_CONFIG.secretAllowedCharacters,
    CSRF_CONFIG.pkceLength
  );
  const verifier = {
    pkce,
    pkceHash: urlSafe.stringify(
      createHash('sha256').update(pkce, 'utf8').digest('base64')
    ),
  };
  return verifier;
}