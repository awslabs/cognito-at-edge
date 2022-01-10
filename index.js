const axios = require('axios');
const querystring = require('querystring');
const pino = require('pino');
const awsJwtVerify = require('aws-jwt-verify');

class Authenticator {
  constructor(params) {
    this._verifyParams(params);
    this._region = params.region;
    this._userPoolId = params.userPoolId;
    this._userPoolAppId = params.userPoolAppId;
    this._userPoolAppSecret = params.userPoolAppSecret;
    this._userPoolDomain = params.userPoolDomain;
    this._cookieExpirationDays = params.cookieExpirationDays || 365;
    this._disableCookieDomain = ('disableCookieDomain' in params && params.disableCookieDomain === true) ? true : false;
    this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
    this._logger = pino({
      level: params.logLevel || 'silent', // Default to silent
      base: null, //Remove pid, hostname and name logging as not usefull for Lambda
    });
    this._jwtVerifier = awsJwtVerify.CognitoJwtVerifier.create({
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
    ['region', 'userPoolId', 'userPoolAppId', 'userPoolDomain'].forEach(param => {
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
      method: 'post',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && { 'Authorization': `Basic ${authorization}` }),
      },
      data: querystring.stringify({
        client_id: this._userPoolAppId,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: redirectURI,
      }),
    };
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
   * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
   * @param  {Object} tokens   Cognito User Pool tokens.
   * @param  {String} domain   Website domain.
   * @param  {String} location Path to redirection.
   * @return {Object} Lambda@Edge response.
   */
  async _getRedirectResponse(tokens, domain, location) {
    const decoded = await this._jwtVerifier.verify(tokens.id_token);
    const username = decoded['cognito:username'];
    const usernameBase = `${this._cookieBase}.${username}`;
    const directives = (!this._disableCookieDomain) ?
      `Domain=${domain}; Expires=${new Date(new Date() * 1 + this._cookieExpirationDays * 864e+5)}; Secure` :
      `Expires=${new Date(new Date() * 1 + this._cookieExpirationDays * 864e+5)}; Secure`;
    const response = {
      status: '302',
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
        'set-cookie': [
          {
            key: 'Set-Cookie',
            value: `${usernameBase}.accessToken=${tokens.access_token}; ${directives}`,
          },
          {
            key: 'Set-Cookie',
            value: `${usernameBase}.idToken=${tokens.id_token}; ${directives}`,
          },
          {
            key: 'Set-Cookie',
            value: `${usernameBase}.refreshToken=${tokens.refresh_token}; ${directives}`,
          },
          {
            key: 'Set-Cookie',
            value: `${usernameBase}.tokenScopesString=phone email profile openid aws.cognito.signin.user.admin; ${directives}`,
          },
          {
            key: 'Set-Cookie',
            value: `${this._cookieBase}.LastAuthUser=${username}; ${directives}`,
          },
        ],
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }

  /**
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookies Request cookies.
   * @return {String} Extracted access token. Throw if not found.
   */
  _getIdTokenFromCookie(cookies) {
    this._logger.debug({ msg: 'Extracting authentication token from request cookie', cookies });
    // eslint-disable-next-line no-useless-escape
    const regex = new RegExp(`${this._userPoolAppId}\..+?\.idToken=(.*?);`);
    if (cookies) {
      for (let i = 0; i < cookies.length; i++) {
        const matches = cookies[i].value.match(regex);
        if (matches && matches.length > 1) {
          this._logger.debug({ msg: '  Found token in cookie', token: matches[1] });
          return matches[1];
        }
      }
    }
    this._logger.debug("  idToken wasn't present in request cookies");
    throw new Error("Id token isn't present in the request cookies");
  }

  /**
   * Handle Lambda@Edge event:
   *   * if authentication cookie is present and valid: forward the request
   *   * if ?code=<grant code> is present: set cookies with new tokens
   *   * else redirect to the Cognito UserPool to authenticate the user
   * @param  {Object}  event Lambda@Edge event.
   * @return {Promise} CloudFront response.
   */
  async handle(event) {
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = querystring.parse(request.querystring);
    const cfDomain = request.headers.host[0].value;
    const redirectURI = `https://${cfDomain}`;

    try {
      const token = this._getIdTokenFromCookie(request.headers.cookie);
      this._logger.debug({ msg: 'Verifying token...', token });
      const user = await this._jwtVerifier.verify(token);
      this._logger.info({ msg: 'Forwarding request', path: request.uri, user });
      return request;
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      if (requestParams.code) {
        return this._fetchTokensFromCode(redirectURI, requestParams.code)
          .then(tokens => this._getRedirectResponse(tokens, cfDomain, requestParams.state));
      } else {
        let redirectPath = request.uri;
        if (request.querystring && request.querystring !== '') {
          redirectPath += encodeURIComponent('?' + request.querystring);
        }
        const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${redirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${redirectPath}`;
        this._logger.debug(`Redirecting user to Cognito User Pool URL ${userPoolUrl}`);
        return {
          status: 302,
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

  /**
   * Check if user is authenticated:
   *   * if authentication cookie is present and valid: return true
   *   * else return false
   * @param  {Object}  event Lambda@Edge event.
   * @return {Boolean} True if user is authenticated.
   */
  async isAuthenticated(event) {
    this._logger.debug({ msg: 'Checking if Lambda@Edge event is authenticated', event });

    const { request } = event.Records[0].cf;

    try {
      const token = this._getIdTokenFromCookie(request.headers.cookie);
      this._logger.debug({ msg: 'Verifying token...', token });
      await this._jwtVerifier.verify(token);

      return true;
    } catch (err) {
      return false;
    }
  }
}

module.exports.Authenticator = Authenticator;
