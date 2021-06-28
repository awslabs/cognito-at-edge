const axios = require('axios');
const jwt = require('jsonwebtoken');

jest.mock('axios');
jest.mock('jwk-to-pem');
jest.mock('jsonwebtoken');

const { Authenticator } = require('../index');

const DATE = new Date('2017');
global.Date = class extends Date {
  constructor() {
    super();
    return DATE;
  }
};

describe('private functions', () => {
  let authenticator;

  beforeEach(() => {
    authenticator = new Authenticator({
      region: 'us-east-1',
      userPoolId: 'us-east-1_abcdef123',
      userPoolAppId: '123456789qwertyuiop987abcd',
      userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
      cookieExpirationDays: 365,
      logLevel: 'error',
    });
  });

  test('JWKS should be false by default', () => {
    expect(authenticator._jwks).toBeFalsy();
  });

  test('should fetch JWKS', () => {
    axios.get.mockResolvedValue({ data: jwksData });
    return authenticator._fetchJWKS('http://something')
      .then(() => {
        expect(authenticator._jwks).toEqual({
          '1234example=': { 'kid': '1234example=', 'alg': 'RS256', 'kty': 'RSA', 'e': 'AQAB', 'n': '1234567890', 'use': 'sig' },
          '5678example=': { 'kid': '5678example=', 'alg': 'RS256', 'kty': 'RSA', 'e': 'AQAB', 'n': '987654321', 'use': 'sig' },
        });
      });
  });

  test('should throw if unable to fetch JWKS', () => {
    axios.get.mockRejectedValue(new Error('Unexpected error'));
    return expect(() => authenticator._fetchJWKS('http://something')).rejects.toThrow();
  });

  test('should get valid decoded token', () => {
    authenticator._jwks = {};
    jwt.decode.mockReturnValueOnce({ header: { kid: 'kid' } });
    jwt.verify.mockReturnValueOnce({ token_use: 'id', attribute: 'valid' });
    expect(authenticator._getVerifiedToken('valid-token')).toEqual({ token_use: 'id', attribute: 'valid' });
  });

  test('should fetch token', () => {
    axios.request.mockResolvedValue({ data: tokenData });

    return authenticator._fetchTokensFromCode('htt://redirect', 'AUTH_CODE')
      .then(res => {
        expect(res).toEqual(tokenData);
      });
  });

  test('should throw if unable to fetch token', () => {
    axios.request.mockRejectedValue(new Error('Unexpected error'));
    return expect(() => authenticator._fetchTokensFromCode('htt://redirect', 'AUTH_CODE')).rejects.toThrow();
  });

  test('should getRedirectResponse', () => {
    const username = 'toto';
    const domain = 'example.com';
    const path = '/test';
    jest.spyOn(authenticator, '_getVerifiedToken');
    authenticator._getVerifiedToken.mockReturnValueOnce({ token_use: 'id', 'cognito:username': username });

    const response = authenticator._getRedirectResponse(tokenData, domain, path);
    expect(response).toMatchObject({
      status: '302',
      headers: {
        location: [{
          key: 'Location',
          value: path,
        }],
      },
    });
    expect(response.headers['set-cookie']).toEqual(expect.arrayContaining([
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone email profile openid aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE}; Secure`},
      {key: 'Set-Cookie', value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE}; Secure`},
    ]));
    expect(authenticator._getVerifiedToken).toHaveBeenCalled();
  });

  test('should getIdTokenFromCookie', () => {
    const appClientName = 'toto,./;;..-_lol123';
    expect(
      authenticator._getIdTokenFromCookie([{
        key: 'Cookie',
        value: `CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.idToken=wrong; CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken=${tokenData.id_token}; CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken=${tokenData.id_token}; CognitoIdentityServiceProvider.5ukasw8840tap1g1i1617jh8pi.${appClientName}.idToken=wrong;`,
      }]),
    ).toBe(tokenData.id_token);
  });

  test('should getIdTokenFromCookie throw on cookies', () => {
    expect(() => authenticator._getIdTokenFromCookie()).toThrow('Id token');
    expect(() => authenticator._getIdTokenFromCookie('')).toThrow('Id token');
    expect(() => authenticator._getIdTokenFromCookie([])).toThrow('Id token');
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
    };
  });

  test('should create authenticator', () => {
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should create authenticator without cookieExpirationDay', () => {
    delete params.cookieExpirationDays;
    expect(typeof new Authenticator(params)).toBe('object');
  });

  test('should fail when creating authenticator without params', () => {
    expect(() => new Authenticator()).toThrow('Expected params');
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

  test('should fail when creating authenticator with invalid cookieExpirationDay', () => {
    params.cookieExpirationDays = '123';
    expect(() => new Authenticator(params)).toThrow('cookieExpirationDays');
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
      logLevel: 'debug',
    });
    authenticator._jwks = jwksData;
    jest.spyOn(authenticator, '_fetchJWKS');
    jest.spyOn(authenticator, '_getVerifiedToken');
    jest.spyOn(authenticator, '_getIdTokenFromCookie');
    jest.spyOn(authenticator, '_fetchTokensFromCode');
    jest.spyOn(authenticator, '_getRedirectResponse');
  });

  test('should fetch JWKS if not present', () => {
    authenticator._jwks = undefined;
    authenticator._fetchJWKS.mockResolvedValueOnce(jwksData);
    return authenticator.handle(getCloudfrontRequest())
      .catch(err => err)
      .finally(() => expect(authenticator._fetchJWKS).toHaveBeenCalled());
  });

  test('should forward request if authenticated', () => {
    authenticator._getVerifiedToken.mockReturnValueOnce({});
    return expect(authenticator.handle(getCloudfrontRequest())).resolves.toEqual(getCloudfrontRequest().Records[0].cf.request)
      .then(() => {
        expect(authenticator._getIdTokenFromCookie).toHaveBeenCalled();
        expect(authenticator._getVerifiedToken).toHaveBeenCalled();
      });
  });

  test('should fetch and set token if code is present', () => {
    authenticator._getVerifiedToken.mockImplementationOnce(() => { throw new Error();});
    authenticator._fetchTokensFromCode.mockResolvedValueOnce(tokenData);
    authenticator._getRedirectResponse.mockReturnValueOnce({ response: 'toto' });
    const request = getCloudfrontRequest();
    request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';
    return expect(authenticator.handle(request)).resolves.toEqual({ response: 'toto' })
      .then(() => {
        expect(authenticator._getVerifiedToken).toHaveBeenCalled();
        expect(authenticator._fetchTokensFromCode).toHaveBeenCalled();
        expect(authenticator._getRedirectResponse).toHaveBeenCalledWith(tokenData, 'd111111abcdef8.cloudfront.net', '/lol');
      });
  });

  test('should redirect to auth domain if unauthenticated and no code', () => {
    authenticator._getVerifiedToken.mockImplementationOnce(() => { throw new Error();});
    return expect(authenticator.handle(getCloudfrontRequest())).resolves.toEqual(
      {
        status: 302,
        headers: {
          location: [{
            key: 'Location',
            value: 'https://my-cognito-domain.auth.us-east-1.amazoncognito.com/authorize?redirect_uri=https://d111111abcdef8.cloudfront.net&response_type=code&client_id=123456789qwertyuiop987abcd&state=/lol%3F%3Fparam%3D1',
          }],
        },
      },
    )
      .then(() => {
        expect(authenticator._getVerifiedToken).toHaveBeenCalled();
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
          "querystring": "?param=1",
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
