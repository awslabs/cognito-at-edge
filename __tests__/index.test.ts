/* eslint-disable @typescript-eslint/ban-ts-comment */
import axios from 'axios';

jest.mock('axios');

import { CloudFrontRequest } from 'aws-lambda';
import { Authenticator } from '../src/';
import { Cookies } from '../src/util/cookie';
import { NONCE_COOKIE_NAME_SUFFIX, NONCE_HMAC_COOKIE_NAME_SUFFIX, PKCE_COOKIE_NAME_SUFFIX } from '../src/util/csrf';

const DATE = new Date('2017');
// @ts-ignore
global.Date = class extends Date {
  constructor() {
    super();
    return DATE;
  }
};

describe('private functions', () => {
  let authenticator : Authenticator;

  beforeEach(() => {
    authenticator = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: false,
      httpOnly: false,
    });
  });

  test('should fetch token', () => {
    axios.request = jest.fn().mockResolvedValue({ data: tokenData });

    return authenticator._fetchTokensFromCode('htt://redirect', 'AUTH_CODE')
      .then(res => {
        expect(res).toMatchObject({refreshToken: tokenData.refresh_token, accessToken: tokenData.access_token, idToken: tokenData.id_token});
      });
  });

  test('should throw if unable to fetch token', () => {
    axios.request = jest.fn().mockRejectedValue(new Error('Unexpected error'));
    return expect(() => authenticator._fetchTokensFromCode('htt://redirect', 'AUTH_CODE')).rejects.toThrow();
  });

  test('should getRedirectResponse', async () => {
    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticator._jwtVerifier, 'verify');
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));

    const response = await authenticator._getRedirectResponse({refreshToken: tokenData.refresh_token, accessToken: tokenData.access_token, idToken: tokenData.id_token}, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response?.headers?.['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`},
    ]));
    expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
  });

  test('should not return cookie domain', async () => {
    const authenticatorWithNoCookieDomain = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: true,
    });
    authenticatorWithNoCookieDomain._jwtVerifier.cacheJwks(jwksData);

    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticatorWithNoCookieDomain._jwtVerifier, 'verify');
    authenticatorWithNoCookieDomain._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));

    const response = await authenticatorWithNoCookieDomain._getRedirectResponse({'accessToken': tokenData.access_token, 'idToken': tokenData.id_token, 'refreshToken': tokenData.refresh_token}, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response?.headers?.['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Expires=${DATE.toUTCString()}; Secure`},
    ]));
    expect(authenticatorWithNoCookieDomain._jwtVerifier.verify).toHaveBeenCalled();
  });

  test('should set HttpOnly on cookies', async () => {
    const authenticatorWithHttpOnly = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: false,
      httpOnly: true,
    });
    authenticatorWithHttpOnly._jwtVerifier.cacheJwks(jwksData);

    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticatorWithHttpOnly._jwtVerifier, 'verify');
    authenticatorWithHttpOnly._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));

    const response = await authenticatorWithHttpOnly._getRedirectResponse({ accessToken: tokenData.access_token, idToken: tokenData.id_token, refreshToken: tokenData.refresh_token }, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response?.headers?.['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
    ]));
    expect(authenticatorWithHttpOnly._jwtVerifier.verify).toHaveBeenCalled();
  });

  test('should set SameSite on cookies', async () => {
    const authenticatorWithSameSite = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: false,
      httpOnly: true,
      sameSite: 'Strict',
    });
    authenticatorWithSameSite._jwtVerifier.cacheJwks(jwksData);

    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticatorWithSameSite._jwtVerifier, 'verify');
    authenticatorWithSameSite._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));

    const response = await authenticatorWithSameSite._getRedirectResponse({ accessToken: tokenData.access_token, idToken: tokenData.id_token, refreshToken: tokenData.refresh_token }, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response?.headers?.['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`},
    ]));
    expect(authenticatorWithSameSite._jwtVerifier.verify).toHaveBeenCalled();
  });

  test('should set Path on cookies', async () => {
    const cookiePath = '/test/path';
    const authenticatorWithPath = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: false,
      cookiePath,
    });
    authenticatorWithPath._jwtVerifier.cacheJwks(jwksData);

    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticatorWithPath._jwtVerifier, 'verify');
    authenticatorWithPath._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));

    const response = await authenticatorWithPath._getRedirectResponse({ accessToken: tokenData.access_token, idToken: tokenData.id_token, refreshToken: tokenData.refresh_token }, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response?.headers?.['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
    ]));
    expect(authenticatorWithPath._jwtVerifier.verify).toHaveBeenCalled();
  });

  test('should set csrf tokens when the feature is enabled', async () => {
    const cookiePath = '/test/path';
    const authenticatorWithPath = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: false,
      cookiePath,
      csrfProtection: {
        nonceSigningSecret: 'foo-bar',
      },
    });
    authenticatorWithPath._jwtVerifier.cacheJwks(jwksData);

    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticatorWithPath._jwtVerifier, 'verify');
    authenticatorWithPath._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));

    const response = await authenticatorWithPath._getRedirectResponse({ accessToken: tokenData.access_token, idToken: tokenData.id_token, refreshToken: tokenData.refresh_token }, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response?.headers?.['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`},
    ]));
    expect(authenticatorWithPath._jwtVerifier.verify).toHaveBeenCalled();
  });

  test('should use overriden cookie settings', async () => {
    const cookiePath = '/test/path';
    const authenticatorWithPath = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: false,
      cookiePath,
      httpOnly: true,
      csrfProtection: {
        nonceSigningSecret: 'foo-bar',
      },
      cookieSettingsOverrides: {
        accessToken: {
          httpOnly: false,
          sameSite: 'Lax',
          path: '/foo',
          expirationDays: 2,
        },
      },
    });
    authenticatorWithPath._jwtVerifier.cacheJwks(jwksData);

    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticatorWithPath._jwtVerifier, 'verify');
    authenticatorWithPath._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));

    const response = await authenticatorWithPath._getRedirectResponse({ accessToken: tokenData.access_token, idToken: tokenData.id_token, refreshToken: tokenData.refresh_token }, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response?.headers?.['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${'/foo'}; Expires=${DATE.toUTCString()}; Secure; SameSite=Lax`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`},
    ]));
    expect(authenticatorWithPath._jwtVerifier.verify).toHaveBeenCalled();
  });

  test('should getIdTokenFromCookie', () => {
    const appClientName = 'toto,./;;..-_lol123';
    expect(
      authenticator._getTokensFromCookie([{
        key: 'Cookie',
        value: [
          Cookies.serialize(`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.idToken`, 'wrong'),
          Cookies.serialize(`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`, tokenData.id_token),
          Cookies.serialize(`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`, tokenData.id_token),
          Cookies.serialize(`CognitoIdentityServiceProvider.5ukasw8840tap1g1i1617jh8pi.${appClientName}.idToken`, 'wrong'),
        ].join('; '),
      }]),
    ).toMatchObject({idToken: tokenData.id_token});

    expect(
      authenticator._getTokensFromCookie([{
        key: 'Cookie',
        value: [
          Cookies.serialize(`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.accessToken`, tokenData.access_token),
          Cookies.serialize(`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`, tokenData.id_token),
        ].join('; '),
      }]),
    ).toMatchObject({ idToken: tokenData.id_token});


    expect(
      authenticator._getTokensFromCookie([{
        key: 'Cookie',
        value: [
          Cookies.serialize(`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.accessToken`, tokenData.access_token),
          Cookies.serialize(`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`, tokenData.id_token),
          Cookies.serialize(`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.refreshToken`, tokenData.refresh_token),
        ].join('; '),
      }]),
    ).toMatchObject({ idToken: tokenData.id_token, refreshToken: tokenData.refresh_token});
  });

  test('should getTokensFromCookie throw on cookies', () => {
    expect(() => authenticator._getTokensFromCookie([])).toThrow('idToken');
  });

  describe('_validateCSRFCookies', () => {
    function buildRequest(tokensInState = {}, tokensInCookie = {}): CloudFrontRequest {
      const state = Buffer.from(JSON.stringify(tokensInState)).toString('base64');

      const cookieHeaders: Array<{ key?: string | undefined; value: string; }> = [];
      for (const [name, value] of Object.entries(tokensInCookie)) {
        cookieHeaders.push({key: 'cookie', value: `${authenticator._cookieBase}.${name}=${value}`});
      }
      return {
        clientIp: '',
        method: '',
        uri: '',
        querystring: `state=${state}`,
        headers: {
          'cookie': cookieHeaders,
        },
      };
    }

    beforeEach(() => {
      authenticator._csrfProtection = {
        nonceSigningSecret: 'foo-bar',
      };
    });

    it('should throw error when nonce cookie is not present', () => {
      const request = buildRequest(
        {nonce: 'nonce-value'},
        {}
      );
      expect(() => authenticator._validateCSRFCookies(request)).toThrow(
        'Your browser didn\'t send the nonce cookie along, but it is required for security (prevent CSRF).',
      );
    });

    it('should throw error when nonce cookie is different than the one encoded in state', () => {
      const request = buildRequest(
        {[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value'},
        {[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value-different'}
      );
      expect(() => authenticator._validateCSRFCookies(request)).toThrow(
        'Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)',
      );
    });

    it('should throw error when pkce cookie is absent', () => {
      const request = buildRequest(
        {[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value', [PKCE_COOKIE_NAME_SUFFIX]: 'pkce-value'},
        {[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value'}
      );
      expect(() => authenticator._validateCSRFCookies(request)).toThrow(
        'Your browser didn\'t send the pkce cookie along, but it is required for security (prevent CSRF).'
      );
    });

    it('should throw error when calculated Hmac is different than the one stored in the cookie', () => {
      jest.mock('../src/util/csrf', () => ({signNonce: () => 'nonce-hmac-value-different'}));
      const request = buildRequest(
        {[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value', [PKCE_COOKIE_NAME_SUFFIX]: 'pkce-value'},
        {[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value', [PKCE_COOKIE_NAME_SUFFIX]: 'pkce-value', [NONCE_HMAC_COOKIE_NAME_SUFFIX]: 'nonce-hmac-value'}
      );
      expect(() => authenticator._validateCSRFCookies(request)).toThrow(
        'Nonce signature mismatch!'
      );
    });
  });

  test('_revokeTokens', () => {
    axios.request = jest.fn().mockResolvedValue({ data: tokenData });
    authenticator._revokeTokens({refreshToken: tokenData.refresh_token});
    expect(axios.request).toHaveBeenCalledWith(expect.objectContaining({
      url: 'https://my-cognito-domain.auth.us-east-1.amazoncognito.com/oauth2/revoke',
      method: 'POST',
    }));
  });

  describe('_clearCookies', () => {
    it('should verify tokens and clear cookies', async () => {
      jest.spyOn(authenticator._jwtVerifier, 'verify');
      authenticator._jwtVerifier.cacheJwks(jwksData);
      authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({}));
      const tokens = {idToken: tokenData.id_token, refreshToken: tokenData.refresh_token};
      const response = await (authenticator as any)._clearCookies(getCloudfrontRequest(), tokens);
      expect(response).toEqual(expect.objectContaining({
        status: '302',
      }));
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'].length).toBe(5);
    });

    it('should clear cookies even if tokens cannot be verified', async () => {
      jest.spyOn(authenticator._jwtVerifier, 'verify');
      authenticator._jwtVerifier.cacheJwks(jwksData);
      authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.reject({}));
      const tokens = {idToken: tokenData.id_token, refreshToken: tokenData.refresh_token};
      const request = getCloudfrontRequest();
      const numCookiesToBeCleared = request.Records[0].cf.request.headers['cookie']?.length || 0;
      const response = await (authenticator as any)._clearCookies(request, tokens);
      expect(response).toEqual(expect.objectContaining({
        status: '302',
      }));
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'].length).toBe(numCookiesToBeCleared);
    });

    it('should clear cookies and redirect to logoutRedirectUri', async () => {
      jest.spyOn(authenticator._jwtVerifier, 'verify');
      authenticator._logoutConfiguration = {
        logoutUri: '/logout',
        logoutRedirectUri: 'https://foobar.com',
      };
      authenticator._jwtVerifier.cacheJwks(jwksData);
      authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({}));
      const tokens = {idToken: tokenData.id_token, refreshToken: tokenData.refresh_token};
      const response = await (authenticator as any)._clearCookies(getCloudfrontRequest(), tokens);
      expect(response).toEqual(expect.objectContaining({ status: '302' }));
      expect(response.headers['location']?.[0]?.value).toEqual('https://foobar.com');
    });

    it('should clear cookies and redirect to redirect_uri query param', async () => {
      jest.spyOn(authenticator._jwtVerifier, 'verify');
      authenticator._jwtVerifier.cacheJwks(jwksData);
      authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({}));
      const request = getCloudfrontRequest();
      request.Records[0].cf.request.querystring = 'redirect_uri=https://foobar.com';
      const response = await (authenticator as any)._clearCookies(request);
      expect(response).toEqual(expect.objectContaining({ status: '302' }));
      expect(response.headers['location']?.[0]?.value).toEqual('https://foobar.com');
    });

    it('should clear cookies and redirect to cf domain', async () => {
      jest.spyOn(authenticator._jwtVerifier, 'verify');
      authenticator._jwtVerifier.cacheJwks(jwksData);
      authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({}));
      const request = getCloudfrontRequest();
      const response = await (authenticator as any)._clearCookies(request);
      expect(response).toEqual(expect.objectContaining({ status: '302' }));
      expect(response.headers['location']?.[0]?.value).toEqual('https://d111111abcdef8.cloudfront.net');
    });
  });

});

describe('createAuthenticator', () => {
  let params;

  beforeEach(() => {
    params = {
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      disableCookieDomain: true,
      httpOnly: false,
    };
  });

  test('should create authenticator', () => {
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should create authenticator without cookieExpirationDays', () => {
    delete params.cookieExpirationDays;
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should create authenticator without disableCookieDomain', () => {
    delete params.disableCookieDomain;
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should create authenticator without cookieDomain', () => {
    delete params.cookieDomain;
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should create authenticator without httpOnly', () => {
    delete params.httpOnly;
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should create authenticator without cookiePath', () => {
    delete params.cookiePath;
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should create authenticator with unvalidated samesite', () => {
    params.sameSite = '123';
    expect(() => new Authenticator(params)).toThrow('Expected params');
  });

  test('should fail when creating authenticator without params', () => {
    // @ts-ignore
    // ts-ignore is used here to override typescript's type check in the constructor
    // this test is still useful when the library is imported to a js file
    expect(() => new Authenticator()).toThrow('Expected params');
  });

  test('should fail when creating authenticator without region', () => {
    delete params.region;
    expect(() => new Authenticator(params)).toThrow('region');
  });

  test('should fail when creating authenticator without userPoolId', () => {
    delete params.userPoolId;
    expect(() => new Authenticator(params)).toThrow('userPoolId');
  });

  test('should fail when creating authenticator without userPoolAppId', () => {
    delete params.userPoolAppId;
    expect(() => new Authenticator(params)).toThrow('userPoolAppId');
  });

  test('should fail when creating authenticator without userPoolDomain', () => {
    delete params.userPoolDomain;
    expect(() => new Authenticator(params)).toThrow('userPoolDomain');
  });

  test('should fail when creating authenticator with invalid region', () => {
    params.region = 123;
    expect(() => new Authenticator(params)).toThrow('region');
  });

  test('should fail when creating authenticator with invalid userPoolId', () => {
    params.userPoolId = 123;
    expect(() => new Authenticator(params)).toThrow('userPoolId');
  });

  test('should fail when creating authenticator with invalid userPoolAppId', () => {
    params.userPoolAppId = 123;
    expect(() => new Authenticator(params)).toThrow('userPoolAppId');
  });

  test('should fail when creating authenticator with invalid userPoolDomain', () => {
    params.userPoolDomain = 123;
    expect(() => new Authenticator(params)).toThrow('userPoolDomain');
  });

  test('should fail when creating authenticator with invalid cookieExpirationDays', () => {
    params.cookieExpirationDays = '123';
    expect(() => new Authenticator(params)).toThrow('cookieExpirationDays');
  });

  test('should fail when creating authenticator with invalid disableCookieDomain', () => {
    params.disableCookieDomain = '123';
    expect(() => new Authenticator(params)).toThrow('disableCookieDomain');
  });

  test('should fail when creating authenticator with invalid cookie domain', () => {
    params.cookieDomain = 123;
    expect(() => new Authenticator(params)).toThrow('cookieDomain');
  });

  test('should fail when creating authenticator with invalid httpOnly', () => {
    params.httpOnly = '123';
    expect(() => new Authenticator(params)).toThrow('httpOnly');
  });

  test('should fail when creating authenticator with invalid cookiePath', () => {
    params.cookiePath = 123;
    expect(() => new Authenticator(params)).toThrow('cookiePath');
  });

  test('should fail when creating authenticator with invalid logoutUri', () => {
    params.logoutConfiguration = { logoutUri: '' };
    expect(() => new Authenticator(params)).toThrow('logoutUri');

    params.logoutConfiguration = { logoutUri: '/' };
    expect(() => new Authenticator(params)).toThrow('logoutUri');
  });
});

describe('handle', () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
    });
    authenticator._jwtVerifier.cacheJwks(jwksData);
    jest.spyOn(authenticator, '_getTokensFromCookie');
    jest.spyOn(authenticator, '_fetchTokensFromCode');
    jest.spyOn(authenticator, '_fetchTokensFromRefreshToken');
    jest.spyOn(authenticator, '_getRedirectResponse');
    jest.spyOn(authenticator, '_getRedirectToCognitoUserPoolResponse');
    jest.spyOn(authenticator, '_revokeTokens');
    jest.spyOn(authenticator, '_clearCookies');
    jest.spyOn(authenticator._jwtVerifier, 'verify');
  });

  test('should forward request if authenticated', () => {
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({}));
    return expect(authenticator.handle(getCloudfrontRequest())).resolves.toEqual(getCloudfrontRequest().Records[0].cf.request)
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
      });
  });

  test('should fetch with refresh token if available', () => {
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.reject({}));
    authenticator._getTokensFromCookie.mockReturnValueOnce({refreshToken: tokenData.refresh_token});
    authenticator._fetchTokensFromRefreshToken.mockResolvedValueOnce(tokenData);
    authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = '';
    return expect(authenticator.handle(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromRefreshToken).toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).toHaveBeenCalledWith(tokenData, 'd111111abcdef8.cloudfront.net', '/lol');
      });
  });

  test('should maintain querystring while refresh token flow', () => {
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.reject({}));
    authenticator._getTokensFromCookie.mockReturnValueOnce({refreshToken: tokenData.refresh_token});
    authenticator._fetchTokensFromRefreshToken.mockResolvedValueOnce(tokenData);
    authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = 'foo=bar';
    return expect(authenticator.handle(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromRefreshToken).toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).toHaveBeenCalledWith(tokenData, 'd111111abcdef8.cloudfront.net', '/lol?foo=bar');
      });
  });

  test('should redirect to cognito if refresh token is invalid', () => {
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.reject({}));
    authenticator._getTokensFromCookie.mockReturnValueOnce({refreshToken: tokenData.refresh_token});
    authenticator._fetchTokensFromRefreshToken.mockReturnValueOnce(Promise.reject({}));
    authenticator._getRedirectToCognitoUserPoolResponse.mockReturnValueOnce({ response: 'toto' });
    const request = getCloudfrontRequest();
    return expect(authenticator.handle(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromRefreshToken).toHaveBeenCalled();
      });
  });

  test('should fetch and set token if code is present', () => {
    authenticator._jwtVerifier.verify.mockImplementationOnce(async () => { throw new Error(); });
    authenticator._fetchTokensFromCode.mockResolvedValueOnce(tokenData);
    authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';
    return expect(authenticator.handle(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromCode).toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).toHaveBeenCalledWith(tokenData, 'd111111abcdef8.cloudfront.net', '/lol');
      });
  });

  test('should fetch and set token if code is present (custom redirect)', () => {
    const authenticatorWithCustomRedirect : any = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      parseAuthPath: '/custom/login/path',
    });
    jest.spyOn(authenticatorWithCustomRedirect._jwtVerifier, 'verify');
    jest.spyOn(authenticatorWithCustomRedirect, '_fetchTokensFromCode');
    jest.spyOn(authenticatorWithCustomRedirect, '_getRedirectResponse');
    authenticatorWithCustomRedirect._jwtVerifier.verify.mockImplementationOnce(async () => { throw new Error(); });
    authenticatorWithCustomRedirect._fetchTokensFromCode.mockResolvedValueOnce(tokenData);
    authenticatorWithCustomRedirect._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';
    return expect(authenticatorWithCustomRedirect.handle(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticatorWithCustomRedirect._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticatorWithCustomRedirect._fetchTokensFromCode).toHaveBeenCalledWith('https://d111111abcdef8.cloudfront.net/custom/login/path', '54fe5f4e');
        expect(authenticatorWithCustomRedirect._getRedirectResponse).toHaveBeenCalledWith(tokenData, 'd111111abcdef8.cloudfront.net', '/lol');
      });
  });


  test('should fetch and set token if code is present and when csrfProtection is enabled', () => {
    authenticator._jwtVerifier.verify.mockImplementationOnce(async () => { throw new Error(); });
    authenticator._fetchTokensFromCode.mockResolvedValueOnce(tokenData);
    authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    authenticator._csrfProtection = {
      nonceSigningSecret: 'foobar',
    };
    const encodedState = Buffer.from(
      JSON.stringify({ redirect_uri: '/lol' })
    ).toString('base64');
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = `code=54fe5f4e&state=${encodedState}`;
    return expect(authenticator.handle(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromCode).toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).toHaveBeenCalledWith(tokenData, 'd111111abcdef8.cloudfront.net', '/lol');
      });
  });

  test('should redirect to auth domain if unauthenticated and no code', () => {
    authenticator._jwtVerifier.verify.mockImplementationOnce(async () => { throw new Error();});
    return expect(authenticator.handle(getCloudfrontRequest())).resolves.toEqual(
      {
        status: '302',
        headers: {
          'location': [{
            key: 'Location',
            value: 'https://my-cognito-domain.auth.us-east-1.amazoncognito.com/authorize?redirect_uri=https://d111111abcdef8.cloudfront.net&response_type=code&client_id=123456789qwertyuiop987abcd&state=/lol%3Fparam%3D1',
          }],
          'cache-control': [{
            key: 'Cache-Control',
            value: 'no-cache, no-store, max-age=0, must-revalidate',
          }],
          'pragma': [{
            key: 'Pragma',
            value: 'no-cache',
          }],
        },
      },
    )
      .then(() => {
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
      });
  });

  test('should redirect to auth domain if unauthenticated and no code (custom redirect)', () => {
    const authenticatorWithCustomRedirect : any = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      parseAuthPath: '/custom/login/path',
    });
    jest.spyOn(authenticatorWithCustomRedirect._jwtVerifier, 'verify');
    authenticator._jwtVerifier.verify.mockImplementationOnce(async () => { throw new Error();});
    return expect(authenticatorWithCustomRedirect.handle(getCloudfrontRequest())).resolves.toEqual(
      {
        status: '302',
        headers: {
          'location': [{
            key: 'Location',
            value: 'https://my-cognito-domain.auth.us-east-1.amazoncognito.com/authorize?redirect_uri=https://d111111abcdef8.cloudfront.net/custom/login/path&response_type=code&client_id=123456789qwertyuiop987abcd&state=/lol%3Fparam%3D1',
          }],
          'cache-control': [{
            key: 'Cache-Control',
            value: 'no-cache, no-store, max-age=0, must-revalidate',
          }],
          'pragma': [{
            key: 'Pragma',
            value: 'no-cache',
          }],
        },
      },
    )
      .then(() => {
        expect(authenticatorWithCustomRedirect._jwtVerifier.verify).toHaveBeenCalled();
      });
  });

  test('should redirect to auth domain and clear csrf cookies if unauthenticated and no code', async () => {
    authenticator._jwtVerifier.verify.mockImplementationOnce(async () => { throw new Error(); });
    authenticator._csrfProtection = {
      nonceSigningSecret: 'foo-bar',
    };
    const response = await authenticator.handle(getCloudfrontRequest());
    expect(response).toMatchObject({
      status: '302',
      headers: {
        'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache, no-store, max-age=0, must-revalidate',
        }],
        'pragma': [{
          key: 'Pragma',
          value: 'no-cache',
        }],
      },
    });
    const url = new URL(response.headers['location'][0].value);
    expect(url.origin).toEqual('https://my-cognito-domain.auth.us-east-1.amazoncognito.com');
    expect(url.pathname).toEqual('/authorize');
    expect(url.searchParams.get('redirect_uri')).toEqual('https://d111111abcdef8.cloudfront.net');
    expect(url.searchParams.get('response_type')).toEqual('code');
    expect(url.searchParams.get('client_id')).toEqual('123456789qwertyuiop987abcd');
    expect(url.searchParams.get('state')).toBeDefined();

    // Cookies
    expect(response.headers['set-cookie']).toBeDefined();
    const cookies = response.headers['set-cookie'].map(h => h.value);
    expect(cookies.find(c => c.match(`.${NONCE_COOKIE_NAME_SUFFIX}=`))).toBeDefined();
    expect(cookies.find(c => c.match(`.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=`))).toBeDefined();
    expect(cookies.find(c => c.match(`.${PKCE_COOKIE_NAME_SUFFIX}=`))).toBeDefined();
  });

  test('should redirect to auth domain with custom return redirect if unauthenticated', async () => {
    const authenticatorWithCustomRedirect : any = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      parseAuthPath: '/custom/login/path',
    });
    jest.spyOn(authenticatorWithCustomRedirect._jwtVerifier, 'verify');
    authenticatorWithCustomRedirect._jwtVerifier.verify.mockImplementationOnce(async () => { throw new Error(); });
    const response = await authenticatorWithCustomRedirect.handle(getCloudfrontRequest());
    const url = new URL(response.headers['location'][0].value);
    expect(url.searchParams.get('redirect_uri')).toEqual('https://d111111abcdef8.cloudfront.net/custom/login/path');
  });

  test('should revoke tokens and clear cookies if logoutConfiguration is set', () => {
    authenticator._logoutConfiguration = { logoutUri: '/logout' };
    authenticator._getTokensFromCookie.mockReturnValueOnce({ refreshToken: tokenData.refresh_token });
    authenticator._revokeTokens.mockReturnValueOnce(Promise.resolve());
    authenticator._clearCookies.mockReturnValueOnce(Promise.resolve({ status: '302' }));
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.uri = '/logout';
    return expect(authenticator.handle(request)).resolves.toEqual(expect.objectContaining({ status: '302' }))
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._revokeTokens).toHaveBeenCalled();
        expect(authenticator._clearCookies).toHaveBeenCalled();
      });
  });

  test('should clear cookies if logoutConfiguration is set even if user is unauthenticated', async () => {
    authenticator._logoutConfiguration = { logoutUri: '/logout' };
    authenticator._getTokensFromCookie.mockImplementationOnce(() => { throw new Error(); });
    authenticator._clearCookies.mockReturnValueOnce(Promise.resolve({ status: '302' }));
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.uri = '/logout';
    return expect(authenticator.handle(request)).resolves.toEqual(expect.objectContaining({ status: '302' }))
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._revokeTokens).not.toHaveBeenCalled();
        expect(authenticator._clearCookies).toHaveBeenCalled();
      });
  });
});

describe('handleSignIn', () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      parseAuthPath: 'parseAuth',
    });
    authenticator._jwtVerifier.cacheJwks(jwksData);
    jest.spyOn(authenticator, '_getTokensFromCookie');
    jest.spyOn(authenticator, '_getRedirectToCognitoUserPoolResponse');
    jest.spyOn(authenticator._jwtVerifier, 'verify');
  });

  test('should forward request if authenticated', async () => {
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({}));
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = 'redirect_uri=https://example.aws.com';
    const response = await authenticator.handleSignIn(request);
    expect(response.status).toEqual('302');
    expect(response.headers?.location).toBeDefined();
    expect(response.headers.location[0].value).toEqual('https://example.aws.com');
  });

  test('should redirect to cognito if refresh token is invalid', () => {
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.reject({}));
    authenticator._getTokensFromCookie.mockReturnValueOnce({refreshToken: tokenData.refresh_token});
    authenticator._getRedirectToCognitoUserPoolResponse.mockReturnValueOnce({ response: 'toto' });
    const request = getCloudfrontRequest();
    return expect(authenticator.handleSignIn(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._getRedirectToCognitoUserPoolResponse).toHaveBeenCalled();
      });
  });
});

describe('handleParseAuth', () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      parseAuthPath: 'parseAuth',
    });
    authenticator._jwtVerifier.cacheJwks(jwksData);
    jest.spyOn(authenticator, '_validateCSRFCookies');
    jest.spyOn(authenticator, '_fetchTokensFromCode');
    jest.spyOn(authenticator, '_getTokensFromCookie');
    jest.spyOn(authenticator, '_getRedirectResponse');
  });

  describe('if code is present', () => {
    test('should redirect successfully if csrfProtection is not enabled', async () => {
      authenticator._fetchTokensFromCode.mockReturnValueOnce(Promise.resolve({
        idToken: tokenData.id_token,
        refreshToken: tokenData.refresh_token,
        accessToken: tokenData.access_token,
      }));
      authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
      const state = Buffer.from(JSON.stringify({
        nonce: 'nonceValue',
        nonceHmac: 'nonceHmacValue',
        pkce: 'pkceValue',
      })).toString('base64');
      const request = getCloudfrontRequest();
      request.Records[0].cf.request.querystring = `code=code&state=${state}`;
      return expect(authenticator.handleParseAuth(request)).resolves.toEqual({ response: 'toto' })
        .then(() => {
          expect(authenticator._validateCSRFCookies).not.toHaveBeenCalled();
          expect(authenticator._fetchTokensFromCode).toHaveBeenCalled();
          expect(authenticator._getRedirectResponse).toHaveBeenCalled();
        });
    });

    test('should redirect successfully after validating CSRF tokens', async () => {
      authenticator._csrfProtection = {
        nonceSigningSecret: 'foo-bar',
      };
      authenticator._validateCSRFCookies.mockReturnValueOnce();
      authenticator._fetchTokensFromCode.mockReturnValueOnce(Promise.resolve({
        idToken: tokenData.id_token,
        refreshToken: tokenData.refresh_token,
        accessToken: tokenData.access_token,
      }));
      authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
      const state = Buffer.from(JSON.stringify({
        nonce: 'nonceValue',
        nonceHmac: 'nonceHmacValue',
        pkce: 'pkceValue',
      })).toString('base64');
      const request = getCloudfrontRequest();
      request.Records[0].cf.request.querystring = `code=code&state=${state}`;
      return expect(authenticator.handleParseAuth(request)).resolves.toEqual({ response: 'toto' })
        .then(() => {
          expect(authenticator._validateCSRFCookies).toHaveBeenCalled();
          expect(authenticator._fetchTokensFromCode).toHaveBeenCalled();
          expect(authenticator._getRedirectResponse).toHaveBeenCalled();
        });
    });
  });

  test('should throw error when parseAuthPath is not set', async () => {
    authenticator._parseAuthPath = '';
    authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    return expect(authenticator.handleParseAuth(getCloudfrontRequest())).resolves.toEqual({ status: '400', body: expect.stringContaining('parseAuthPath')})
      .then(() => {
        expect(authenticator._validateCSRFCookies).not.toHaveBeenCalled();
        expect(authenticator._fetchTokensFromCode).not.toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).not.toHaveBeenCalled();
      });
  });

  test('should throw if code is absent', async () => {
    authenticator._validateCSRFCookies.mockImplementationOnce(async () => { throw new Error(); });
    return expect(authenticator.handleParseAuth(getCloudfrontRequest())).resolves.toEqual(expect.objectContaining({ status: '400' }))
      .then(() => {
        expect(authenticator._validateCSRFCookies).not.toHaveBeenCalled();
        expect(authenticator._fetchTokensFromCode).not.toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).not.toHaveBeenCalled();
      });
  });
});

describe('handleRefreshToken', () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
    });
    authenticator._jwtVerifier.cacheJwks(jwksData);
    jest.spyOn(authenticator, '_getTokensFromCookie');
    jest.spyOn(authenticator._jwtVerifier, 'verify');
    jest.spyOn(authenticator, '_fetchTokensFromRefreshToken');
    jest.spyOn(authenticator, '_getRedirectResponse');
    jest.spyOn(authenticator, '_getRedirectToCognitoUserPoolResponse');
  });

  test('should refresh tokens successfully', async () => {
    const username = 'toto';
    authenticator._getTokensFromCookie.mockReturnValueOnce({ refreshToken: tokenData.refresh_token });
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.resolve({ token_use: 'id', 'cognito:username': username }));
    authenticator._fetchTokensFromRefreshToken.mockReturnValueOnce(Promise.resolve({
      idToken: tokenData.id_token,
      refreshToken: tokenData.refresh_token,
      accessToken: tokenData.access_token,
    }));
    authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    return expect(authenticator.handleRefreshToken(getCloudfrontRequest())).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromRefreshToken).toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).toHaveBeenCalled();
      });
  });

  test('should redirect to cognito user pool if refresh token is invalid', () => {
    authenticator._getTokensFromCookie.mockReturnValueOnce({ refreshToken: tokenData.refresh_token });
    authenticator._jwtVerifier.verify.mockReturnValueOnce(Promise.reject());
    return expect(authenticator.handleRefreshToken(getCloudfrontRequest())).resolves.toEqual(expect.objectContaining({ status: '302' }))
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._jwtVerifier.verify).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromRefreshToken).not.toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).not.toHaveBeenCalled();
      });
  });
});

describe('handleSignOut', () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
    });
    authenticator._jwtVerifier.cacheJwks(jwksData);
    jest.spyOn(authenticator, '_getTokensFromCookie');
    jest.spyOn(authenticator, '_revokeTokens');
    jest.spyOn(authenticator, '_clearCookies');
  });

  test('should revoke tokens and clear cookies successfully', async () => {
    authenticator._getTokensFromCookie.mockReturnValueOnce({ refreshToken: tokenData.refresh_token });
    authenticator._revokeTokens.mockReturnValueOnce(Promise.resolve());
    authenticator._clearCookies.mockReturnValueOnce(Promise.resolve({ status: '302' }));
    return expect(authenticator.handleSignOut(getCloudfrontRequest())).resolves.toEqual(expect.objectContaining({ status: '302' }))
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._revokeTokens).toHaveBeenCalled();
        expect(authenticator._clearCookies).toHaveBeenCalled();
      });
  });

  test('should clear cookies successfully even if tokens cannot be revoked', async () => {
    authenticator._getTokensFromCookie.mockReturnValueOnce({ refreshToken: tokenData.refresh_token });
    authenticator._revokeTokens.mockReturnValueOnce(Promise.reject());
    authenticator._clearCookies.mockReturnValueOnce(Promise.resolve({ status: '302' }));
    return expect(authenticator.handleSignOut(getCloudfrontRequest())).resolves.toEqual(expect.objectContaining({ status: '302' }))
      .then(() => {
        expect(authenticator._getTokensFromCookie).toHaveBeenCalled();
        expect(authenticator._revokeTokens).toHaveBeenCalled();
        expect(authenticator._clearCookies).toHaveBeenCalled();
      });
  });
});
/* eslint-disable quotes, comma-dangle */

const jwksData = {
  "keys": [
    { "kid": "1234example=", "alg": "RS256", "kty": "RSA", "e": "AQAB", "n": "1234567890", "use": "sig" },
    { "kid": "5678example=", "alg": "RS256", "kty": "RSA", "e": "AQAB", "n": "987654321", "use": "sig" },
  ]
};

const tokenData = {
  "access_token":"eyJz9sdfsdfsdfsd",
  "refresh_token":"dn43ud8uj32nk2je",
  "id_token":"dmcxd329ujdmkemkd349r",
  "token_type":"Bearer",
  'expires_in':3600,
};

const getCloudfrontRequest = () => ({
  "Records": [
    {
      "cf": {
        "config": {
          "distributionDomainName": "d123.cloudfront.net",
          "distributionId": "EDFDVBD6EXAMPLE",
          "eventType": "viewer-request",
          "requestId": "MRVMF7KydIvxMWfJIglgwHQwZsbG2IhRJ07sn9AkKUFSHS9EXAMPLE=="
        },
        "request": {
          "body": {
            "action": "read-only",
            "data": "eyJ1c2VybmFtZSI6IkxhbWJkYUBFZGdlIiwiY29tbWVudCI6IlRoaXMgaXMgcmVxdWVzdCBib2R5In0=",
            "encoding": "base64",
            "inputTruncated": false
          },
          "clientIp": "2001:0db8:85a3:0:0:8a2e:0370:7334",
          "querystring": "param=1",
          "uri": "/lol",
          "method": "GET",
          "headers": {
            "host": [
              {
                "key": "Host",
                "value": "d111111abcdef8.cloudfront.net"
              }
            ],
            "user-agent": [
              {
                "key": "User-Agent",
                "value": "curl/7.51.0"
              },
            ],
            "cookie": [
              {
                key: 'cookie',
                value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.idToken=${tokenData.access_token};`
              }
            ]
          },
          "origin": {
            "custom": {
              "customHeaders": {
                "my-origin-custom-header": [
                  {
                    "key": "My-Origin-Custom-Header",
                    "value": "Test"
                  }
                ]
              },
              "domainName": "example.com",
              "keepaliveTimeout": 5,
              "path": "/custom_path",
              "port": 443,
              "protocol": "https",
              "readTimeout": 5,
              "sslProtocols": [
                "TLSv1",
                "TLSv1.1"
              ]
            },
            "s3": {
              "authMethod": "origin-access-identity",
              "customHeaders": {
                "my-origin-custom-header": [
                  {
                    "key": "My-Origin-Custom-Header",
                    "value": "Test"
                  }
                ]
              },
              "domainName": "my-bucket.s3.amazonaws.com",
              "path": "/s3_path",
              "region": "us-east-1"
            }
          }
        }
      }
    }
  ]
});
