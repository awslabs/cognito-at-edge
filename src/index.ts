import axios from 'axios';
import { parse, stringify } from 'querystring';
import pino from 'pino';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { CloudFrontRequestEvent, CloudFrontRequestResult } from 'aws-lambda';
import { CookieAttributes, Cookies, SameSite, SAME_SITE_VALUES } from './util/cookie';



interface AuthenticatorParams {
  region: string;
  userPoolId: string;
  userPoolAppId: string;
  userPoolAppSecret?: string;
  userPoolDomain: string;
  cookieExpirationDays?: number;
  disableCookieDomain?: boolean;
  httpOnly?: boolean;
  sameSite?: SameSite;
  enableLogout?: boolean;
  logLevel?: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
}

export class Authenticator {
  _region: string;
  _userPoolId: string;
  _userPoolAppId: string;
  _userPoolAppSecret: string;
  _userPoolDomain: string;
  _cookieExpirationDays: number;
  _disableCookieDomain: boolean;
  _httpOnly: boolean;
  _sameSite?: SameSite;
  _enableLogout?: boolean;
  _cookieBase: string;
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
    this._httpOnly = ('httpOnly' in params && params.httpOnly === true);
    this._enableLogout = params.enableLogout || false;
    this._sameSite = params.sameSite;
    this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
    this._logger = pino({
      level: params.logLevel || 'silent', // Default to silent
      base: null, //Remove pid, hostname and name logging as not usefull for Lambda
    });
    this._jwtVerifier = CognitoJwtVerifier.create({
      userPoolId: params.userPoolId,
      clientId: params.userPoolAppId,
      tokenUse: 'id',
    });
  }

  /**
   * Verify that constructor parameters are corrects.
   * @param  {object} params constructor params
   * @return {void} throw an exception if params are incorects.
   */
  _verifyParams(params) {
    if (typeof params !== 'object') {
      throw new Error('Expected params to be an object');
    }
    [ 'region', 'userPoolId', 'userPoolAppId', 'userPoolDomain' ].forEach(param => {
      if (typeof params[param] !== 'string') {
        throw new Error(`Expected params.${param} to be a string`);
      }
    });
    if (params.cookieExpirationDays && typeof params.cookieExpirationDays !== 'number') {
      throw new Error('Expected params.cookieExpirationDays to be a number');
    }
    if ('disableCookieDomain' in params && typeof params.disableCookieDomain !== 'boolean') {
      throw new Error('Expected params.disableCookieDomain to be a boolean');
    }
    if ('httpOnly' in params && typeof params.httpOnly !== 'boolean') {
      throw new Error('Expected params.httpOnly to be a boolean');
    }
    if ('enableLogout' in params && typeof params.enableLogout !== 'boolean') {
      throw new Error('Expected params.enableLogout to be a boolean');
    }
    if ('sameSite' in params && !SAME_SITE_VALUES.includes(params.sameSite)) {
      throw new Error('Expected params.sameSite to be a Strict || Lax || None');
    }
  }

  /**
   * Exchange authorization code for tokens.
   * @param  {String} redirectURI Redirection URI.
   * @param  {String} code        Authorization code.
   * @return {Promise} Authenticated user tokens.
   */
  _fetchTokensFromCode(redirectURI, code) {
    const authorization = this._userPoolAppSecret && Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString('base64');
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
        return resp.data;
      })
      .catch(err => {
        this._logger.error({ msg: 'Unable to fetch tokens from grant code', request, code });
        throw err;
      });
  }

  /**
   * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies, or expire cookies on logout.
   * @param  {Object} tokens   Cognito User Pool tokens.
   * @param  {String} domain   Website domain.
   * @param  {String} location Path to redirection.
   * @return {Object} Lambda@Edge response.
   */
  async _getRedirectResponse(tokens, domain, location, expireCookies) {
    const decoded = await this._jwtVerifier.verify(tokens.id_token);
    const username = decoded['cognito:username'];
    const usernameBase = `${this._cookieBase}.${username}`;
    const cookieAttributes: CookieAttributes = {
      domain: this._disableCookieDomain ? undefined : domain,
      expires: expireCookies ? new Date(0) : new Date(Date.now() + this._cookieExpirationDays * 864e+5),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
    };
    const cookies = [
      Cookies.serialize(`${usernameBase}.accessToken`, tokens.access_token, cookieAttributes),
      Cookies.serialize(`${usernameBase}.idToken`, tokens.id_token, cookieAttributes),
      Cookies.serialize(`${usernameBase}.refreshToken`, tokens.refresh_token, cookieAttributes),
      Cookies.serialize(`${usernameBase}.tokenScopesString`, 'phone email profile openid aws.cognito.signin.user.admin', cookieAttributes),
      Cookies.serialize(`${this._cookieBase}.LastAuthUser`, username, cookieAttributes),
    ];

    const response = {
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
   * @return {String} Extracted access token. Throw if not found.
   */
  _getIdTokenFromCookie(cookieHeaders: Array<{ key?: string | undefined, value: string }> | undefined) {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }
    
    this._logger.debug({ msg: 'Extracting authentication token from request cookie', cookieHeaders });

    const tokenCookieNamePrefix = `${this._cookieBase}.`;
    const tokenCookieNamePostfix = '.idToken';

    const cookies = cookieHeaders.flatMap(h => Cookies.parse(h.value));
    const token = cookies.find(c => c.name.startsWith(tokenCookieNamePrefix) && c.name.endsWith(tokenCookieNamePostfix))?.value;

    if (!token) {
      this._logger.debug("idToken wasn't present in request cookies");
      throw new Error("idToken isn't present in the request cookies");
    }

    this._logger.debug({ msg: 'Found idToken in cookie', token });
    return token;
  }

  /**
   * Handle Lambda@Edge event:
   *   * if requested /logout, expire cookies and forward to logout endpoint
   *   * if authentication cookie is present and valid: forward the request
   *   * if ?code=<grant code> is present: set cookies with new tokens
   *   * else redirect to the Cognito UserPool to authenticate the user
   * @param  {Object}  event Lambda@Edge event.
   * @return {Promise} CloudFront response.
   */
  async handle(event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult> {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const cfDomain = request.headers.host[0].value;
    const redirectURI = `https://${cfDomain}`;

    try {
      if (this._enableLogout && request.uri === "/logout") {
        this._logger.debug({ msg: 'Logging out', event});
        
        const tokens = {
          access_token: "0",
          refresh_token: "0",
          id_token: this._getIdTokenFromCookie(request.headers.cookie)
        };

        const expireCookies = true;
        const logoutUrl = `https://${this._userPoolDomain}/logout?logout_uri=${redirectURI}&client_id=${this._userPoolAppId}`;
        return this._getRedirectResponse(tokens, cfDomain, logoutUrl, expireCookies);
      }
    } catch(err) {
      this._logger.error({ msg: 'Failed to logout', err});
    }

    try {
      const token = this._getIdTokenFromCookie(request.headers.cookie);
      this._logger.debug({ msg: 'Verifying token...', token });
      const user = await this._jwtVerifier.verify(token);
      this._logger.info({ msg: 'Forwarding request', path: request.uri, user });
      return request;
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      if (requestParams.code) {
        const expireCookies = false;
        return this._fetchTokensFromCode(redirectURI, requestParams.code)
          .then(tokens => this._getRedirectResponse(tokens, cfDomain, requestParams.state, expireCookies));
      } else {
        let redirectPath = request.uri;
        if (request.querystring && request.querystring !== '') {
          redirectPath += encodeURIComponent('?' + request.querystring);
        }
        const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${redirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${redirectPath}`;
        this._logger.debug(`Redirecting user to Cognito User Pool URL ${userPoolUrl}`);
        return {
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
          },
        };
      }
    }
  }
}
