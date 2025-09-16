import { CognitoJwtVerifier } from 'aws-jwt-verify';
import type { CloudFrontRequest, CloudFrontRequestEvent, CloudFrontResultResponse } from 'aws-lambda';
import axios from 'axios';
import pino from 'pino';
import { parse, stringify } from 'querystring';
import { CookieAttributes, CookieSettingsOverrides, CookieType, Cookies, SAME_SITE_VALUES, SameSite, getCookieDomain } from './util/cookie';
import { CSRFTokens, NONCE_COOKIE_NAME_SUFFIX, NONCE_HMAC_COOKIE_NAME_SUFFIX, PKCE_COOKIE_NAME_SUFFIX, generateCSRFTokens, signNonce, urlSafe } from './util/csrf';

export interface AuthenticatorParams {
  region: string;
  userPoolId: string;
  userPoolAppId: string;
  userPoolAppSecret?: string;
  userPoolDomain: string;
  cookieExpirationDays?: number;
  disableCookieDomain?: boolean;
  httpOnly?: boolean;
  sameSite?: SameSite;
  logLevel?: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
  cookiePath?: string;
  cookieDomain?: string;
  cookieSettingsOverrides?: CookieSettingsOverrides;
  logoutConfiguration?: LogoutConfiguration;
  parseAuthPath?: string;
  csrfProtection?: {
    nonceSigningSecret: string;
  },
}

interface LogoutConfiguration {
  logoutUri: string;
  logoutRedirectUri: string;
}

interface Tokens {
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
}

export class Authenticator {
  _region: string;
  _userPoolId: string;
  _userPoolAppId: string;
  _userPoolAppSecret: string | undefined;
  _userPoolDomain: string;
  _cookieExpirationDays: number;
  _disableCookieDomain: boolean;
  _httpOnly: boolean;
  _sameSite?: SameSite;
  _cookieBase: string;
  _cookiePath?: string;
  _cookieDomain?: string;
  _csrfProtection?: {
    nonceSigningSecret: string;
  };
  _logoutConfiguration?: LogoutConfiguration;
  _parseAuthPath?: string;
  _cookieSettingsOverrides?: CookieSettingsOverrides;
  _logger;
  _jwtVerifier;

  constructor(params: AuthenticatorParams) {
    this._verifyParams(params);
    this._region = params.region;
    this._userPoolId = params.userPoolId;
    this._userPoolAppId = params.userPoolAppId;
    this._userPoolAppSecret = params.userPoolAppSecret;
    this._userPoolDomain = params.userPoolDomain;
    this._cookieExpirationDays = params.cookieExpirationDays || 365;
    this._disableCookieDomain = ('disableCookieDomain' in params && params.disableCookieDomain === true);
    this._cookieDomain = params.cookieDomain;
    this._httpOnly = ('httpOnly' in params && params.httpOnly === true);
    this._sameSite = params.sameSite;
    this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
    this._cookiePath = params.cookiePath;
    this._cookieSettingsOverrides = params.cookieSettingsOverrides || {};
    this._logger = pino({
      level: params.logLevel || 'silent', // Default to silent
      base: null, //Remove pid, hostname and name logging as not usefull for Lambda
    });
    this._jwtVerifier = CognitoJwtVerifier.create({
      userPoolId: params.userPoolId,
      clientId: params.userPoolAppId,
      tokenUse: 'id',
    });
    this._csrfProtection = params.csrfProtection;
    this._logoutConfiguration = params.logoutConfiguration;
    this._parseAuthPath = (params.parseAuthPath || '').replace(/^\//, '');
  }

  /**
   * Verify that constructor parameters are corrects.
   * @param  {object} params constructor params
   * @return {void} throw an exception if params are incorects.
   */
  _verifyParams(params: AuthenticatorParams) {
    if (typeof params !== 'object') {
      throw new Error('Expected params to be an object');
    }
    [ 'region', 'userPoolId', 'userPoolAppId', 'userPoolDomain' ].forEach(param => {
      if (typeof params[param as keyof AuthenticatorParams] !== 'string') {
        throw new Error(`Expected params.${param} to be a string`);
      }
    });
    if (params.cookieExpirationDays && typeof params.cookieExpirationDays !== 'number') {
      throw new Error('Expected params.cookieExpirationDays to be a number');
    }
    if ('disableCookieDomain' in params && typeof params.disableCookieDomain !== 'boolean') {
      throw new Error('Expected params.disableCookieDomain to be boolean');
    }
    if ('cookieDomain' in params && typeof params.cookieDomain !== 'string') {
      throw new Error('Expected params.cookieDomain to be a string');
    }
    if ('httpOnly' in params && typeof params.httpOnly !== 'boolean') {
      throw new Error('Expected params.httpOnly to be a boolean');
    }
    if (params.sameSite !== undefined && !SAME_SITE_VALUES.includes(params.sameSite)) {
      throw new Error('Expected params.sameSite to be a Strict || Lax || None');
    }
    if ('cookiePath' in params && typeof params.cookiePath !== 'string') {
      throw new Error('Expected params.cookiePath to be a string');
    }
    if (params.logoutConfiguration && !/\/\w+/.test(params.logoutConfiguration.logoutUri)) {
      throw new Error('Expected params.logoutConfiguration.logoutUri to be a valid non-empty string starting with "/"');
    }
  }

  /**
   * Exchange authorization code for tokens.
   * @param  {String} redirectURI Redirection URI.
   * @param  {String} code        Authorization code.
   * @return {Promise} Authenticated user tokens.
   */
  _fetchTokensFromCode(redirectURI: string, code: string): Promise<Tokens> {
    const authorization = this._getAuthorization();
    const request = {
      url: `https://${this._userPoolDomain}/oauth2/token`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && {'Authorization': `Basic ${authorization}`}),
      },
      data: stringify({
        client_id:	this._userPoolAppId,
        code:	code,
        grant_type:	'authorization_code',
        redirect_uri:	redirectURI,
      }),
    } as const;
    this._logger.debug({ msg: 'Fetching tokens from grant code...', request, code });
    return axios.request(request)
      .then(resp => {
        this._logger.debug({ msg: 'Fetched tokens', tokens: resp.data });
        return {
          idToken: resp.data.id_token,
          accessToken: resp.data.access_token,
          refreshToken: resp.data.refresh_token,
        };
      })
      .catch(err => {
        this._logger.error({ msg: 'Unable to fetch tokens from grant code', request, code });
        throw err;
      });
  }

  /**
   * Fetch accessTokens from refreshToken.
   * @param  {String} redirectURI Redirection URI.
   * @param  {String} refreshToken Refresh token.
   * @return {Promise<Tokens>} Refreshed user tokens.
   */
  _fetchTokensFromRefreshToken(redirectURI: string, refreshToken: string): Promise<Tokens> {
    const authorization = this._getAuthorization();
    const request = {
      url: `https://${this._userPoolDomain}/oauth2/token`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && {'Authorization': `Basic ${authorization}`}),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        redirect_uri: redirectURI,
      }),
    } as const;
    this._logger.debug({ msg: 'Fetching tokens from refreshToken...', request, refreshToken });
    return axios.request(request)
      .then(resp => {
        this._logger.debug({ msg: 'Fetched tokens', tokens: resp.data });
        return {
          idToken: resp.data.id_token,
          accessToken: resp.data.access_token,
        };
      })
      .catch(err => {
        this._logger.error({ msg: 'Unable to fetch tokens from refreshToken', request, refreshToken });
        throw err;
      });
  }

  _getAuthorization(): string | undefined {
    return this._userPoolAppSecret && Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString('base64');
  }

  _validateCSRFCookies(request: CloudFrontRequest) {
    if (!this._csrfProtection) {
      throw new Error('_validateCSRFCookies should not be called if CSRF protection is disabled.');
    }
    
    const requestParams = parse(request.querystring);
    const requestCookies = request.headers.cookie?.flatMap(h => Cookies.parse(h.value)) || [];
    this._logger.debug({ msg: 'Validating CSRF Cookies', requestCookies});

    const parsedState = JSON.parse(
      Buffer.from(urlSafe.parse(requestParams.state as string), 'base64').toString()
    );

    const {nonce: originalNonce, nonceHmac, pkce} = this._getCSRFTokensFromCookie(request.headers.cookie);

    if (
      !parsedState.nonce ||
      !originalNonce ||
      parsedState.nonce !== originalNonce
    ) {
      if (!originalNonce) {
        throw new Error('Your browser didn\'t send the nonce cookie along, but it is required for security (prevent CSRF).');
      }
      throw new Error('Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)');
    }
    if (!pkce) {
      throw new Error('Your browser didn\'t send the pkce cookie along, but it is required for security (prevent CSRF).');
    }

    const calculatedHmac = signNonce(parsedState.nonce, this._csrfProtection.nonceSigningSecret);

    if (calculatedHmac !== nonceHmac) {
      throw new Error(`Nonce signature mismatch! Expected ${calculatedHmac} but got ${nonceHmac}`);
    }
  }

  _getOverridenCookieAttributes(cookieAttributes: CookieAttributes = {}, cookieType: CookieType): CookieAttributes {
    const res = {...cookieAttributes};
    
    const overrides = this._cookieSettingsOverrides?.[cookieType];
    if (overrides) {
      if (overrides.httpOnly !== undefined) {
        res.httpOnly = overrides.httpOnly;
      }
      if (overrides.sameSite !== undefined) {
        res.sameSite = overrides.sameSite;
      }
      if (overrides.path !== undefined) {
        res.path = overrides.path;
      }
      if (overrides.expirationDays !== undefined) {
        res.expires = new Date(Date.now() + overrides.expirationDays * 864e+5);
      }
    }
    this._logger.debug({
      msg: 'Cookie settings overriden',
      cookieAttributes,
      cookieType,
      cookieSettingsOverrides: this._cookieSettingsOverrides,
    });
    return res;
  }

  /**
   * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
   * @param  {Object} tokens   Cognito User Pool tokens.
   * @param  {String} domain   Website domain.
   * @param  {String} location Path to redirection.
   * @return Lambda@Edge response.
   */
  async _getRedirectResponse(tokens: Tokens, domain: string, location: string): Promise<CloudFrontResultResponse> {
    const decoded = await this._jwtVerifier.verify(tokens.idToken as string);
    const username = decoded['cognito:username'] as string;
    const usernameBase = `${this._cookieBase}.${username}`;
    const cookieDomain = getCookieDomain(domain, this._disableCookieDomain, this._cookieDomain);
    const cookieAttributes: CookieAttributes = {
      domain: cookieDomain,
      expires: new Date(Date.now() + this._cookieExpirationDays * 864e+5),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
      path: this._cookiePath,
    };
    const cookies = [
      Cookies.serialize(`${usernameBase}.accessToken`, tokens.accessToken as string, this._getOverridenCookieAttributes(cookieAttributes, 'accessToken')),
      Cookies.serialize(`${usernameBase}.idToken`, tokens.idToken as string, this._getOverridenCookieAttributes(cookieAttributes, 'idToken')),
      ...(tokens.refreshToken ? [Cookies.serialize(`${usernameBase}.refreshToken`, tokens.refreshToken, this._getOverridenCookieAttributes(cookieAttributes, 'refreshToken'))] : []),
      Cookies.serialize(`${usernameBase}.tokenScopesString`, 'phone email profile openid aws.cognito.signin.user.admin', cookieAttributes),
      Cookies.serialize(`${this._cookieBase}.LastAuthUser`, username, cookieAttributes),
    ];

    // Clear CSRF Token Cookies
    if (this._csrfProtection) {
      // Domain attribute is always not set here as CSRF cookies are used
      // exclusively by the CF distribution
      const csrfCookieAttributes = {...cookieAttributes, domain: undefined, expires: new Date()};
      cookies.push(
        Cookies.serialize(`${this._cookieBase}.${PKCE_COOKIE_NAME_SUFFIX}`, '', csrfCookieAttributes),
        Cookies.serialize(`${this._cookieBase}.${NONCE_COOKIE_NAME_SUFFIX}`, '', csrfCookieAttributes),
        Cookies.serialize(`${this._cookieBase}.${NONCE_HMAC_COOKIE_NAME_SUFFIX}`, '', csrfCookieAttributes),
      );
    }

    const response: CloudFrontResultResponse = {
      status: '302' ,
      headers: {
        'location': [{
          key: 'Location',
          value: location,
        }],
        'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache, no-store, max-age=0, must-revalidate',
        }],
        'pragma': [{
          key: 'Pragma',
          value: 'no-cache',
        }],
        'set-cookie': cookies.map(c => ({ key: 'Set-Cookie', value: c })),
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }

  /**
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {Tokens} Extracted id token or access token. Null if not found.
   */
  _getTokensFromCookie(cookieHeaders: Array<{ key?: string | undefined, value: string }> | undefined): Tokens {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({ msg: 'Extracting authentication token from request cookie', cookieHeaders });

    const cookies = cookieHeaders.flatMap(h => Cookies.parse(h.value));

    const tokenCookieNamePrefix = `${this._cookieBase}.`;
    const idTokenCookieNamePostfix = '.idToken';
    const refreshTokenCookieNamePostfix = '.refreshToken';

    const tokens: Tokens = {};
    for (const {name, value} of cookies){
      if (name.startsWith(tokenCookieNamePrefix) && name.endsWith(idTokenCookieNamePostfix)) {
        tokens.idToken = value;
      }
      if (name.startsWith(tokenCookieNamePrefix) && name.endsWith(refreshTokenCookieNamePostfix)) {
        tokens.refreshToken = value;
      }
    }

    if (!tokens.idToken && !tokens.refreshToken) {
      this._logger.debug('Neither idToken, nor refreshToken was present in request cookies');
      throw new Error('Neither idToken, nor refreshToken was present in request cookies');
    }

    this._logger.debug({ msg: 'Found tokens in cookie', tokens });
    return tokens;
  }

  /**
   * Extract values of the CSRF tokens from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {CSRFTokens} Extracted CSRF Tokens from cookie.
   */
  _getCSRFTokensFromCookie(cookieHeaders: Array<{ key?: string | undefined, value: string }> | undefined): CSRFTokens {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({ msg: 'Extracting CSRF tokens from request cookie', cookieHeaders });

    const cookies = cookieHeaders.flatMap(h => Cookies.parse(h.value));
    const csrfTokens: CSRFTokens = cookies.reduce((tokens, {name, value}) => {
      if (name.startsWith(this._cookieBase)) {
        [
          NONCE_COOKIE_NAME_SUFFIX,
          NONCE_HMAC_COOKIE_NAME_SUFFIX,
          PKCE_COOKIE_NAME_SUFFIX,
        ].forEach(key => {
          if (name.endsWith(`.${key}`)) {
            tokens[key] = value;
          }
        });
      }
      return tokens;
    }, {} as CSRFTokens);

    this._logger.debug({ msg: 'Found CSRF tokens in cookie', csrfTokens });
    return csrfTokens;
  }

  /**
   * Extracts the redirect uri from the state param. When CSRF protection is
   * enabled, redirect uri is encoded inside state along with other data. So, it
   * needs to be base64 decoded. When CSRF is not enabled, state can be used
   * directly.
   * @param {string} state
   * @returns {string}
   */
  _getRedirectUriFromState(state: string): string {
    if (this._csrfProtection) {
      const parsedState = JSON.parse(
        Buffer.from(urlSafe.parse(state), 'base64').toString()
      );
      this._logger.debug({ msg: 'Parsed state param to extract redirect uri', parsedState });
      return parsedState.redirect_uri;
    }
    return state;
  }

  async _revokeTokens(tokens: Tokens) {
    const authorization = this._getAuthorization();
    const revokeRequest = {
      url: `https://${this._userPoolDomain}/oauth2/revoke`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && {'Authorization': `Basic ${authorization}`}),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        token: tokens.refreshToken,
      }),
    } as const;
    this._logger.debug({ msg: 'Revoking refreshToken...', request: revokeRequest, refreshToken: tokens.refreshToken });
    return axios.request(revokeRequest)
      .then(() => {
        this._logger.debug({ msg: 'Revoked refreshToken', refreshToken: tokens.refreshToken });
      })
      .catch(err => {
        this._logger.error({ msg: 'Unable to revoke refreshToken', request: revokeRequest, err: JSON.stringify(err) });
        throw err;
      });
  }

  async _clearCookies(event: CloudFrontRequestEvent, tokens: Tokens = {}): Promise<CloudFrontResultResponse> {
    this._logger.info({ msg: 'Clearing cookies...', event, tokens });
    const { request } = event.Records[0].cf;
    const cfDomain = request.headers.host[0].value;
    const requestParams = parse(request.querystring);
    const redirectURI = this._logoutConfiguration?.logoutRedirectUri ||
      requestParams.redirect_uri as string ||
      `https://${cfDomain}`;

    const cookieDomain = getCookieDomain(cfDomain, this._disableCookieDomain, this._cookieDomain);
    const cookieAttributes: CookieAttributes = {
      domain: cookieDomain,
      expires: new Date(),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
      path: this._cookiePath,
    };

    let responseCookies: string[] = [];
    try {
      const decoded = await this._jwtVerifier.verify(tokens.idToken as string);
      const username = decoded['cognito:username'] as string;
      this._logger.info({ msg: 'Token verified. Clearing cookies...', idToken: tokens.idToken, username });

      const usernameBase = `${this._cookieBase}.${username}`;
      responseCookies = [
        Cookies.serialize(`${usernameBase}.accessToken`, '', cookieAttributes),
        Cookies.serialize(`${usernameBase}.idToken`, '', cookieAttributes),
        ...(tokens.refreshToken ? [Cookies.serialize(`${usernameBase}.refreshToken`, '', cookieAttributes)] : []),
        Cookies.serialize(`${usernameBase}.tokenScopesString`, '', cookieAttributes),
        Cookies.serialize(`${this._cookieBase}.LastAuthUser`, '', cookieAttributes),
      ];
    } catch (err) {
      this._logger.info({
        msg: 'Unable to verify token. Inferring data from request cookies and clearing them...',
        idToken: tokens.idToken,
      });
      const requestCookies = request.headers.cookie?.flatMap(h => Cookies.parse(h.value)) || [];
      for (const { name } of requestCookies) {
        if (name.startsWith(this._cookieBase)) {
          responseCookies.push(
            Cookies.serialize(name, '', cookieAttributes),
          );
        }
      }
    }

    const response: CloudFrontResultResponse = {
      status: '302' ,
      headers: {
        'location': [{
          key: 'Location',
          value: redirectURI,
        }],
        'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache, no-store, max-age=0, must-revalidate',
        }],
        'pragma': [{
          key: 'Pragma',
          value: 'no-cache',
        }],
        'set-cookie': responseCookies.map(c => ({ key: 'Set-Cookie', value: c })),
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }

  /**
   * Get redirect to cognito userpool response
   * @param  {CloudFrontRequest}  request The original request
   * @param  {string}  redirectURI Redirection URI.
   * @return {CloudFrontResultResponse} Redirect response.
   */
  _getRedirectToCognitoUserPoolResponse(request: CloudFrontRequest, redirectURI: string): CloudFrontResultResponse {
    let redirectPath = request.uri;
    if (request.querystring && request.querystring !== '') {
      redirectPath += encodeURIComponent('?' + request.querystring);
    }

    let csrfTokens: CSRFTokens = {};
    let state: string | undefined = redirectPath;
    if (this._csrfProtection) {
      csrfTokens = generateCSRFTokens(redirectURI, this._csrfProtection.nonceSigningSecret);
      state = csrfTokens.state;
    }

    const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${redirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${state}`;

    this._logger.debug(`Redirecting user to Cognito User Pool URL ${userPoolUrl}`);
  
    let cookies: string[] | undefined;
    if (this._csrfProtection) {
      const cookieAttributes: CookieAttributes = {
        expires: new Date(Date.now() + 10 * 60 * 1000),
        secure: true,
        httpOnly: this._httpOnly,
        sameSite: this._sameSite,
        path: this._cookiePath,
      };
      cookies = [
        Cookies.serialize(`${this._cookieBase}.${PKCE_COOKIE_NAME_SUFFIX}`, csrfTokens.pkce || '', cookieAttributes),
        Cookies.serialize(`${this._cookieBase}.${NONCE_COOKIE_NAME_SUFFIX}`, csrfTokens.nonce || '', cookieAttributes),
        Cookies.serialize(`${this._cookieBase}.${NONCE_HMAC_COOKIE_NAME_SUFFIX}`, csrfTokens.nonceHmac || '', cookieAttributes),
      ];
    }

    const response: CloudFrontResultResponse = {
      status: '302',
      headers: {
        'location': [{
          key: 'Location',
          value: userPoolUrl,
        }],
        'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache, no-store, max-age=0, must-revalidate',
        }],
        'pragma': [{
          key: 'Pragma',
          value: 'no-cache',
        }],
        ...(cookies
          ? { 'set-cookie': cookies && cookies.map(c => ({ key: 'Set-Cookie', value: c })) }
          : {}),
      },
    };
  
    return response;
  }

  /**
   * Handle Lambda@Edge event:
   *   * if authentication cookie is present and valid: forward the request
   *   * if authentication cookie is invalid, but refresh token is present: set cookies with refreshed tokens
   *   * if ?code=<grant code> is present: set cookies with new tokens
   *   * else redirect to the Cognito UserPool to authenticate the user
   * @param  {Object}  event Lambda@Edge event.
   * @return {Promise} CloudFront response.
   */
  async handle(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse | CloudFrontRequest> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const cfDomain = request.headers.host[0].value;
    const redirectURI = this._parseAuthPath ? `https://${cfDomain}/${this._parseAuthPath}` : `https://${cfDomain}`;

    try {
      const tokens = this._getTokensFromCookie(request.headers.cookie);
      if (this._logoutConfiguration && request.uri.startsWith(this._logoutConfiguration.logoutUri)) {
        this._logger.info({ msg: 'Revoking tokens', tokens });
        await this._revokeTokens(tokens);

        this._logger.info({ msg: 'Revoked tokens. Clearing cookies', tokens });
        return this._clearCookies(event, tokens);
      }
      try {
        this._logger.debug({ msg: 'Verifying token...', tokens });
        const user = await this._jwtVerifier.verify(tokens.idToken as string);
        this._logger.info({ msg: 'Forwarding request', path: request.uri, user });
        return request;
      } catch (err) {
        this._logger.info({ msg: 'Token verification failed', tokens, refreshToken: tokens.refreshToken });
        if (tokens.refreshToken) {
          this._logger.debug({ msg: 'Verifying idToken failed, verifying refresh token instead...', tokens, err });
          return await this._fetchTokensFromRefreshToken(redirectURI, tokens.refreshToken)
            .then(tokens => this._getRedirectResponse(tokens, cfDomain, request.querystring ? `${request.uri}?${request.querystring}` : request.uri));
        } else {
          throw err;
        }
      }
    } catch (err) {
      if (this._logoutConfiguration && request.uri.startsWith(this._logoutConfiguration.logoutUri)) {
        this._logger.info({ msg: 'Clearing cookies', path: cfDomain });
        return this._clearCookies(event);
      }
      this._logger.debug("User isn't authenticated: %s", err);

      const requestParams = parse(request.querystring);
      if (requestParams.code) {
        return this._fetchTokensFromCode(redirectURI, requestParams.code as string)
          .then(tokens => this._getRedirectResponse(tokens, cfDomain, this._getRedirectUriFromState(requestParams.state as string)));
      } else {
        return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
      }
    }
  }

  /**
   *
   * 1. If the token cookies are present in the request, send users to the redirect_uri
   * 2. If cookies are not present, initiate the authentication flow
   *
   * @param event Event that triggers this Lambda function
   * @returns Lambda response
   */
  async handleSignIn(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const cfDomain = request.headers.host[0].value;
    const redirectURI = requestParams.redirect_uri as string || `https://${cfDomain}`;

    try {
      const tokens = this._getTokensFromCookie(request.headers.cookie);

      this._logger.debug({ msg: 'Verifying token...', tokens });
      const user = await this._jwtVerifier.verify(tokens.idToken as string);

      this._logger.info({ msg: 'Redirecting user to', path: redirectURI, user });
      return {
        status: '302',
        headers: {
          'location': [{
            key: 'Location',
            value: redirectURI,
          }],
        },
      };
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      return this._getRedirectToCognitoUserPoolResponse(
        request, this._parseAuthPath ? `https://${cfDomain}/${this._parseAuthPath}` : redirectURI,
      );
    }
  }

  /**
   * 
   * Handler that performs OAuth token exchange -- exchanges the authorization
   * code obtained from the query parameter from server for tokens -- and sets
   * tokens as cookies. This is done after performing CSRF checks, by verifying
   * that the information encoded in the state query parameter is related to the
   * one stored in the cookies.
   * 
   * @param event Event that triggers this Lambda function
   * @returns Lambda response
   */
  async handleParseAuth(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const cfDomain = request.headers.host[0].value;
    const requestParams = parse(request.querystring);

    try {
      if (!this._parseAuthPath) {
        throw new Error('parseAuthPath is not set');
      }
      const redirectURI = `https://${cfDomain}/${this._parseAuthPath}`;
      if (requestParams.code) {
        if (this._csrfProtection) {
          this._validateCSRFCookies(request);
        }
        const tokens = await this._fetchTokensFromCode(redirectURI, requestParams.code as string);
        const location = this._getRedirectUriFromState(requestParams.state as string);

        return this._getRedirectResponse(tokens, cfDomain, location);
      } else {
        this._logger.debug({msg: 'Code param not found', requestParams});
        throw new Error('OAuth code parameter not found');
      }
    } catch (err) {
      this._logger.debug({msg: 'Unable to exchange code for tokens', err});
      return {
        status: '400',
        body: `${err}`,
      };
    }
  }

  /**
   * 
   * Uses the refreshToken present in the cookies to get a new set of tokens
   * from the authorization server. After fetching the tokens, they are sent
   * back to the client as cookies.
   * 
   * @param event Event that triggers this Lambda function
   * @returns Lambda response
   */
  async handleRefreshToken(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const cfDomain = request.headers.host[0].value;
    const requestParams = parse(request.querystring);
    const redirectURI = requestParams.redirect_uri as string || `https://${cfDomain}`;

    try {
      let tokens = this._getTokensFromCookie(request.headers.cookie);

      this._logger.debug({ msg: 'Verifying token...', tokens });
      const user = await this._jwtVerifier.verify(tokens.idToken as string);

      this._logger.debug({ msg: 'Refreshing tokens...', tokens, user });
      tokens = await this._fetchTokensFromRefreshToken(redirectURI, tokens.refreshToken as string);

      this._logger.debug({ msg: 'Refreshed tokens...', tokens, user });
      return this._getRedirectResponse(tokens, cfDomain, redirectURI);
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      return this._getRedirectToCognitoUserPoolResponse(
        request, this._parseAuthPath ? `https://${cfDomain}/${this._parseAuthPath}` : redirectURI,
      );
    }
  }

  /**
   * 
   * Revokes the refreshToken (which also invalidates the accessToken obtained
   * using that refreshToken) and clears the cookies. Even if the revoke
   * operation fails, clear cookies based on the cookie names present in the
   * request headers.
   * 
   * @param event Event that triggers this Lambda function
   * @returns Lambda response
   */
  async handleSignOut(event: CloudFrontRequestEvent): Promise<CloudFrontResultResponse> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const cfDomain = request.headers.host[0].value;
    const redirectURI = requestParams.redirect_uri as string || `https://${cfDomain}`;

    try {
      const tokens = this._getTokensFromCookie(request.headers.cookie);

      this._logger.info({ msg: 'Revoking tokens', tokens });
      await this._revokeTokens(tokens);

      this._logger.info({ msg: 'Revoked tokens. Clearing cookies...', tokens });
      return this._clearCookies(event, tokens);
    } catch (err) {
      this._logger.info({ msg: 'Unable to revoke tokens. Clearing cookies...', path: redirectURI });
      return this._clearCookies(event);
    }
  }
}

