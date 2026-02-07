/* eslint-disable @typescript-eslint/ban-ts-comment */
import axios from 'axios';

jest.mock('axios');

import {
	CloudFrontRequest,
	CloudFrontRequestEvent,
	CloudFrontResultResponse,
} from 'aws-lambda';
import { Authenticator, AuthenticatorParams } from '../src/';
import { serializeCookie, SameSite } from '../src/util/cookie';
import {
	NONCE_COOKIE_NAME_SUFFIX,
	NONCE_HMAC_COOKIE_NAME_SUFFIX,
	PKCE_COOKIE_NAME_SUFFIX,
} from '../src/util/csrf';
import type {
	CognitoJwtVerifierSingleUserPool,
	CognitoJwtVerifierMultiUserPool,
} from 'aws-jwt-verify/cognito-verifier';

const DATE = new Date('2017');
// @ts-ignore
global.Date = class extends Date {
	constructor() {
		super();
		return DATE;
	}
};

// Test helper class that exposes private methods for testing
class TestAuthenticator extends Authenticator {
	public _fetchTokensFromCode = super._fetchTokensFromCode.bind(this);
	public _fetchTokensFromRefreshToken = super._fetchTokensFromRefreshToken.bind(
		this,
	);
	public _getRedirectResponse = super._getRedirectResponse.bind(this);
	public _getTokensFromCookie = super._getTokensFromCookie.bind(this);
	public _getCSRFTokensFromCookie = super._getCSRFTokensFromCookie.bind(this);
	public _getRedirectUriFromState = super._getRedirectUriFromState.bind(this);
	public _revokeTokens = super._revokeTokens.bind(this);
	public _clearCookies = super._clearCookies.bind(this);
	public _getRedirectToCognitoUserPoolResponse =
		super._getRedirectToCognitoUserPoolResponse.bind(this);
	public _validateCSRFCookies = super._validateCSRFCookies.bind(this);
	public _getOverridenCookieAttributes =
		super._getOverridenCookieAttributes.bind(this);

	// Properties are accessed directly from parent class
	// TypeScript doesn't allow overriding properties with accessors, so we just declare the types

	declare public _jwtVerifier: // eslint-disable-next-line @typescript-eslint/no-explicit-any
		| CognitoJwtVerifierSingleUserPool<any>
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		| CognitoJwtVerifierMultiUserPool<any>;
	declare public _cookieBase: string;
	declare public _csrfProtection: AuthenticatorParams['csrfProtection'];
	declare public _logoutConfiguration: AuthenticatorParams['logoutConfiguration'];
	declare public _parseAuthPath: string;
}

describe('private functions', () => {
	let authenticator: TestAuthenticator;

	beforeEach(() => {
		authenticator = new TestAuthenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			cookieExpirationDays: 365,
			disableCookieDomain: false,
			httpOnly: false,
		});
	});

	afterEach(() => {
		jest.restoreAllMocks();
	});

	test('should fetch token', () => {
		axios.request = jest.fn().mockResolvedValue({ data: tokenData });

		return authenticator
			._fetchTokensFromCode('htt://redirect', 'AUTH_CODE')
			.then((res) => {
				expect(res).toMatchObject({
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				});
			});
	});

	test('should throw if unable to fetch token', () => {
		axios.request = jest.fn().mockRejectedValue(new Error('Unexpected error'));
		return expect(() =>
			authenticator._fetchTokensFromCode('htt://redirect', 'AUTH_CODE'),
		).rejects.toThrow();
	});

	test('should getRedirectResponse', async () => {
		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticator._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const response = await authenticator._getRedirectResponse(
			{
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
			},
			domain,
			path,
		);
		expect(response).toMatchObject({
			status: '302',
			headers: {
				location: [
					{
						key: 'Location',
						value: 'https://' + domain + path,
					},
				],
			},
		});
		expect(response.headers?.['set-cookie']).toEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalled();
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
		authenticatorWithNoCookieDomain._jwtVerifier.cacheJwks(
			jwksData,
			'us-east-1_abcdef123',
		);

		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticatorWithNoCookieDomain._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const response = await authenticatorWithNoCookieDomain._getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		);
		expect(response).toMatchObject({
			status: '302',
			headers: {
				location: [
					{
						key: 'Location',
						value: 'https://' + domain + path,
					},
				],
			},
		});
		expect(response.headers?.['set-cookie']).toEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Expires=${DATE.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalled();
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
		authenticatorWithHttpOnly._jwtVerifier.cacheJwks(
			jwksData,
			'us-east-1_abcdef123',
		);

		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticatorWithHttpOnly._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const response = await authenticatorWithHttpOnly._getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		);
		expect(response).toMatchObject({
			status: '302',
			headers: {
				location: [
					{
						key: 'Location',
						value: 'https://' + domain + path,
					},
				],
			},
		});
		expect(response.headers?.['set-cookie']).toEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalled();
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
		authenticatorWithSameSite._jwtVerifier.cacheJwks(
			jwksData,
			'us-east-1_abcdef123',
		);

		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticatorWithSameSite._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const response = await authenticatorWithSameSite._getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		);
		expect(response).toMatchObject({
			status: '302',
			headers: {
				location: [
					{
						key: 'Location',
						value: 'https://' + domain + path,
					},
				],
			},
		});
		expect(response.headers?.['set-cookie']).toEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${DATE.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalled();
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
		authenticatorWithPath._jwtVerifier.cacheJwks(
			jwksData,
			'us-east-1_abcdef123',
		);

		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticatorWithPath._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const response = await authenticatorWithPath._getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		);
		expect(response).toMatchObject({
			status: '302',
			headers: {
				location: [
					{
						key: 'Location',
						value: 'https://' + domain + path,
					},
				],
			},
		});
		expect(response.headers?.['set-cookie']).toEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalled();
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
		authenticatorWithPath._jwtVerifier.cacheJwks(
			jwksData,
			'us-east-1_abcdef123',
		);

		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticatorWithPath._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const response = await authenticatorWithPath._getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		);
		expect(response).toMatchObject({
			status: '302',
			headers: {
				location: [
					{
						key: 'Location',
						value: 'https://' + domain + path,
					},
				],
			},
		});
		expect(response.headers?.['set-cookie']).toEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalled();
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
		authenticatorWithPath._jwtVerifier.cacheJwks(
			jwksData,
			'us-east-1_abcdef123',
		);

		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticatorWithPath._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const response = await authenticatorWithPath._getRedirectResponse(
			{
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			},
			domain,
			path,
		);
		expect(response).toMatchObject({
			status: '302',
			headers: {
				location: [
					{
						key: 'Location',
						value: 'https://' + domain + path,
					},
				],
			},
		});
		expect(response.headers?.['set-cookie']).toEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=/foo; Expires=${DATE.toUTCString()}; Secure; SameSite=Lax`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${DATE.toUTCString()}; Secure; HttpOnly`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalled();
	});

	test('should getIdTokenFromCookie', () => {
		const appClientName = 'toto,./;;..-_lol123';
		expect(
			authenticator._getTokensFromCookie([
				{
					key: 'Cookie',
					value: [
						serializeCookie(
							`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.idToken`,
							'wrong',
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.5ukasw8840tap1g1i1617jh8pi.${appClientName}.idToken`,
							'wrong',
						),
					].join('; '),
				},
			]),
		).toMatchObject({ idToken: tokenData.id_token });

		expect(
			authenticator._getTokensFromCookie([
				{
					key: 'Cookie',
					value: [
						serializeCookie(
							`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.accessToken`,
							tokenData.access_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
					].join('; '),
				},
			]),
		).toMatchObject({ idToken: tokenData.id_token });

		expect(
			authenticator._getTokensFromCookie([
				{
					key: 'Cookie',
					value: [
						serializeCookie(
							`CognitoIdentityServiceProvider.5uka3k8840tap1g1i1617jh8pi.${appClientName}.accessToken`,
							tokenData.access_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.idToken`,
							tokenData.id_token,
						),
						serializeCookie(
							`CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${appClientName}.refreshToken`,
							tokenData.refresh_token,
						),
					].join('; '),
				},
			]),
		).toMatchObject({
			idToken: tokenData.id_token,
			refreshToken: tokenData.refresh_token,
		});
	});

	test('should getTokensFromCookie throw on cookies', () => {
		expect(() => authenticator._getTokensFromCookie([])).toThrow('idToken');
	});

	describe('_validateCSRFCookies', () => {
		function buildRequest(
			tokensInState = {},
			tokensInCookie = {},
		): CloudFrontRequest {
			const state = Buffer.from(JSON.stringify(tokensInState)).toString(
				'base64',
			);

			const cookieHeaders: Array<{ key?: string | undefined; value: string }> =
				[];
			for (const [name, value] of Object.entries(tokensInCookie)) {
				cookieHeaders.push({
					key: 'cookie',
					value: `${authenticator._cookieBase}.${name}=${String(value)}`,
				});
			}
			return {
				clientIp: '',
				method: '',
				uri: '',
				querystring: `state=${state}`,
				headers: {
					cookie: cookieHeaders,
				},
			};
		}

		beforeEach(() => {
			authenticator._csrfProtection = {
				nonceSigningSecret: 'foo-bar',
			};
		});

		it('should throw error when nonce cookie is not present', () => {
			const request = buildRequest({ nonce: 'nonce-value' }, {});
			expect(() => {
				authenticator._validateCSRFCookies(request);
			}).toThrow(
				"Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).",
			);
		});

		it('should throw error when nonce cookie is different than the one encoded in state', () => {
			const request = buildRequest(
				{ [NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value' },
				{ [NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value-different' },
			);
			expect(() => {
				authenticator._validateCSRFCookies(request);
			}).toThrow(
				'Nonce mismatch. This can happen if you start multiple authentication attempts in parallel (e.g. in separate tabs)',
			);
		});

		it('should throw error when pkce cookie is absent', () => {
			const request = buildRequest(
				{
					[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value',
					[PKCE_COOKIE_NAME_SUFFIX]: 'pkce-value',
				},
				{ [NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value' },
			);
			expect(() => {
				authenticator._validateCSRFCookies(request);
			}).toThrow(
				"Your browser didn't send the pkce cookie along, but it is required for security (prevent CSRF).",
			);
		});

		it('should throw error when calculated Hmac is different than the one stored in the cookie', () => {
			jest.mock('../src/util/csrf', () => ({
				signNonce: () => 'nonce-hmac-value-different',
			}));
			const request = buildRequest(
				{
					[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value',
					[PKCE_COOKIE_NAME_SUFFIX]: 'pkce-value',
				},
				{
					[NONCE_COOKIE_NAME_SUFFIX]: 'nonce-value',
					[PKCE_COOKIE_NAME_SUFFIX]: 'pkce-value',
					[NONCE_HMAC_COOKIE_NAME_SUFFIX]: 'nonce-hmac-value',
				},
			);
			expect(() => {
				authenticator._validateCSRFCookies(request);
			}).toThrow('Nonce signature mismatch!');
		});
	});

	test('_revokeTokens', async () => {
		const spyAxiosRequest = jest
			.spyOn(axios, 'request')
			.mockResolvedValue({ data: tokenData });
		await authenticator._revokeTokens({
			refreshToken: tokenData.refresh_token,
		});
		expect(spyAxiosRequest).toHaveBeenCalledWith(
			expect.objectContaining({
				url: 'https://my-cognito-domain.auth.us-east-1.amazoncognito.com/oauth2/revoke',
				method: 'POST',
			}),
		);
	});

	describe('_clearCookies', () => {
		it('should verify tokens and clear cookies', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockResolvedValueOnce(createMockCognitoPayload());
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const tokens = {
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			};
			const response = await authenticator._clearCookies(
				getCloudfrontRequest(),
				tokens,
			);
			expect(response).toEqual(
				expect.objectContaining({
					status: '302',
				}),
			);
			expect(response.headers?.['set-cookie'].length).toBe(5);
		});

		it('should clear cookies even if tokens cannot be verified', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockReturnValueOnce(Promise.reject(new Error()));
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const tokens = {
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			};
			const request = getCloudfrontRequest();
			const numCookiesToBeCleared =
				request.Records[0].cf.request.headers['cookie'].length || 0;
			const response = await authenticator._clearCookies(request, tokens);
			expect(response).toEqual(
				expect.objectContaining({
					status: '302',
				}),
			);
			expect(response.headers?.['set-cookie'].length).toBe(
				numCookiesToBeCleared,
			);
		});

		it('should clear cookies and redirect to logoutRedirectUri', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockResolvedValueOnce(createMockCognitoPayload());
			authenticator._logoutConfiguration = {
				logoutUri: '/logout',
				logoutRedirectUri: 'https://foobar.com',
			};
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const tokens = {
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			};
			const response = await authenticator._clearCookies(
				getCloudfrontRequest(),
				tokens,
			);
			expect(response).toEqual(expect.objectContaining({ status: '302' }));
			expect(response.headers?.['location']?.[0]?.value).toEqual(
				'https://foobar.com',
			);
		});

		it('should clear cookies and redirect to redirect_uri query param', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockResolvedValueOnce(createMockCognitoPayload());
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const request = getCloudfrontRequest();
			request.Records[0].cf.request.querystring =
				'redirect_uri=https://foobar.com';
			const response = await authenticator._clearCookies(request);
			expect(response).toEqual(expect.objectContaining({ status: '302' }));
			expect(response.headers?.['location']?.[0]?.value).toEqual(
				'https://foobar.com',
			);
		});

		it('should clear cookies and redirect to cf domain', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockResolvedValueOnce(createMockCognitoPayload());
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const request = getCloudfrontRequest();
			const response = await authenticator._clearCookies(request);
			expect(response).toEqual(expect.objectContaining({ status: '302' }));
			expect(response.headers?.['location']?.[0]?.value).toEqual(
				'https://d111111abcdef8.cloudfront.net',
			);
		});
	});
});

describe('createAuthenticator', () => {
	const params: AuthenticatorParams = {
		region: 'us-east-1',
		userPoolId: 'us-east-1_abcdef123',
		userPoolAppId: '123456789qwertyuiop987abcd',
		userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
		cookieDomain: 'test.example.com',
		cookieExpirationDays: 365,
		disableCookieDomain: true,
		httpOnly: false,
	};

	test('should create authenticator', () => {
		expect(typeof new Authenticator(params)).toBe('object');
	});

	test('should create authenticator without cookieExpirationDays', () => {
		const { cookieExpirationDays, ...rest } = params;
		expect(typeof new Authenticator(rest)).toBe('object');
	});

	test('should create authenticator without disableCookieDomain', () => {
		const { disableCookieDomain, ...rest } = params;
		expect(typeof new Authenticator(rest)).toBe('object');
	});

	test('should create authenticator without cookieDomain', () => {
		const { cookieDomain, ...rest } = params;
		expect(typeof new Authenticator(rest)).toBe('object');
	});

	test('should create authenticator without httpOnly', () => {
		const { httpOnly, ...rest } = params;
		expect(typeof new Authenticator(rest)).toBe('object');
	});

	test('should create authenticator without cookiePath', () => {
		const { cookiePath, ...rest } = params;
		expect(typeof new Authenticator(rest)).toBe('object');
	});

	test('should fail when creating authenticator with unvalidated samesite', () => {
		expect(
			() =>
				new Authenticator({ ...params, sameSite: 123 as unknown as SameSite }),
		).toThrow('Expected params');
	});

	test('should fail when creating authenticator without params', () => {
		// @ts-ignore
		// ts-ignore is used here to override typescript's type check in the constructor
		// this test is still useful when the library is imported to a js file
		expect(() => new Authenticator()).toThrow('Expected params');
	});

	test('should fail when creating authenticator without region', () => {
		const { region, ...rest } = params;
		expect(() => new Authenticator(rest as AuthenticatorParams)).toThrow(
			'region',
		);
	});

	test('should fail when creating authenticator without userPoolId', () => {
		const { userPoolId, ...rest } = params;
		expect(() => new Authenticator(rest as AuthenticatorParams)).toThrow(
			'userPoolId',
		);
	});

	test('should fail when creating authenticator without userPoolAppId', () => {
		const { userPoolAppId, ...rest } = params;
		expect(() => new Authenticator(rest as AuthenticatorParams)).toThrow(
			'userPoolAppId',
		);
	});

	test('should fail when creating authenticator without userPoolDomain', () => {
		const { userPoolDomain, ...rest } = params;
		expect(() => new Authenticator(rest as AuthenticatorParams)).toThrow(
			'userPoolDomain',
		);
	});

	test('should fail when creating authenticator with invalid region', () => {
		expect(
			() => new Authenticator({ ...params, region: 123 as unknown as string }),
		).toThrow('region');
	});

	test('should fail when creating authenticator with invalid userPoolId', () => {
		expect(
			() =>
				new Authenticator({ ...params, userPoolId: 123 as unknown as string }),
		).toThrow('userPoolId');
	});

	test('should fail when creating authenticator with invalid userPoolAppId', () => {
		expect(
			() =>
				new Authenticator({
					...params,
					userPoolAppId: 123 as unknown as string,
				}),
		).toThrow('userPoolAppId');
	});

	test('should fail when creating authenticator with invalid userPoolDomain', () => {
		expect(
			() =>
				new Authenticator({
					...params,
					userPoolDomain: 123 as unknown as string,
				}),
		).toThrow('userPoolDomain');
	});

	test('should fail when creating authenticator with invalid cookieExpirationDays', () => {
		expect(
			() =>
				new Authenticator({
					...params,
					cookieExpirationDays: '123' as unknown as number,
				}),
		).toThrow('cookieExpirationDays');
	});

	test('should fail when creating authenticator with invalid disableCookieDomain', () => {
		expect(
			() =>
				new Authenticator({
					...params,
					disableCookieDomain: 123 as unknown as boolean,
				}),
		).toThrow('disableCookieDomain');
	});

	test('should fail when creating authenticator with invalid cookie domain', () => {
		expect(
			() =>
				new Authenticator({
					...params,
					cookieDomain: 123 as unknown as string,
				}),
		).toThrow('cookieDomain');
	});

	test('should fail when creating authenticator with invalid httpOnly', () => {
		expect(
			() =>
				new Authenticator({ ...params, httpOnly: 123 as unknown as boolean }),
		).toThrow('httpOnly');
	});

	test('should fail when creating authenticator with invalid cookiePath', () => {
		expect(
			() =>
				new Authenticator({ ...params, cookiePath: 123 as unknown as string }),
		).toThrow('cookiePath');
	});

	test('should fail when creating authenticator with invalid logoutUri', () => {
		expect(
			() =>
				new Authenticator({
					...params,
					logoutConfiguration: {
						logoutUri: '',
					} as AuthenticatorParams['logoutConfiguration'],
				}),
		).toThrow('logoutUri');
		expect(
			() =>
				new Authenticator({
					...params,
					logoutConfiguration: {
						logoutUri: '/',
					} as AuthenticatorParams['logoutConfiguration'],
				}),
		).toThrow('logoutUri');
	});
});

describe('handle', () => {
	let authenticator: TestAuthenticator;
	let spyJwtVerify: jest.SpyInstance;
	let spyGetTokensFromCookie: jest.SpyInstance;
	let spyGetTokensFromCode: jest.SpyInstance;
	let spyFetchTokensFromRefreshToken: jest.SpyInstance;
	let spyGetRedirectResponse: jest.SpyInstance;
	let spyGetRedirectToCognitoUserPoolResponse: jest.SpyInstance;
	let spyRevokeTokens: jest.SpyInstance;
	let spyClearCookies: jest.SpyInstance;

	beforeEach(() => {
		authenticator = new TestAuthenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			cookieExpirationDays: 365,
		});
		authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
		spyGetTokensFromCookie = jest.spyOn(authenticator, '_getTokensFromCookie');
		spyGetTokensFromCode = jest.spyOn(authenticator, '_fetchTokensFromCode');
		spyFetchTokensFromRefreshToken = jest.spyOn(
			authenticator,
			'_fetchTokensFromRefreshToken',
		);
		spyGetRedirectResponse = jest.spyOn(authenticator, '_getRedirectResponse');
		spyGetRedirectToCognitoUserPoolResponse = jest.spyOn(
			authenticator,
			'_getRedirectToCognitoUserPoolResponse',
		);
		spyRevokeTokens = jest.spyOn(authenticator, '_revokeTokens');
		spyClearCookies = jest.spyOn(authenticator, '_clearCookies');
		spyJwtVerify = jest.spyOn(authenticator._jwtVerifier, 'verify');
	});

	test('should forward request if authenticated', () => {
		spyJwtVerify.mockReturnValueOnce(
			Promise.resolve({
				token_use: 'id',
				sub: 'test-sub',
				iss: 'test-iss',
				exp: 0,
				iat: 0,
				auth_time: 0,
				jti: 'test-jti',
				origin_jti: 'test-origin-jti',
			}),
		);
		return expect(authenticator.handle(getCloudfrontRequest()))
			.resolves.toEqual(getCloudfrontRequest().Records[0].cf.request)
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyJwtVerify).toHaveBeenCalled();
			});
	});

	test('should fetch with refresh token if available', () => {
		spyJwtVerify.mockReturnValueOnce(Promise.reject(new Error()));
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyFetchTokensFromRefreshToken.mockResolvedValueOnce(tokenData);
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';
		return expect(authenticator.handle(request))
			.resolves.toEqual({ response: 'toto' })
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyFetchTokensFromRefreshToken).toHaveBeenCalled();
				expect(spyGetRedirectResponse).toHaveBeenCalledWith(
					tokenData,
					'd111111abcdef8.cloudfront.net',
					'/lol',
				);
			});
	});

	test('should redirect to cognito if refresh token is invalid', () => {
		spyJwtVerify.mockReturnValueOnce(Promise.reject(new Error()));
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyFetchTokensFromRefreshToken.mockReturnValueOnce(
			Promise.reject(new Error()),
		);
		spyGetRedirectToCognitoUserPoolResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();
		return expect(authenticator.handle(request))
			.resolves.toEqual({ response: 'toto' })
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyFetchTokensFromRefreshToken).toHaveBeenCalled();
			});
	});

	test('should fetch and set token if code is present', () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());
		spyGetTokensFromCode.mockResolvedValueOnce(tokenData);
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';
		return expect(authenticator.handle(request))
			.resolves.toEqual({ response: 'toto' })
			.then(() => {
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyGetTokensFromCode).toHaveBeenCalled();
				expect(spyGetRedirectResponse).toHaveBeenCalledWith(
					tokenData,
					'd111111abcdef8.cloudfront.net',
					'/lol',
				);
			});
	});

	test('should fetch and set token if code is present (custom redirect)', () => {
		const authenticatorWithCustomRedirect = new Authenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			parseAuthPath: '/custom/login/path',
		});
		const spyJwtVerify = jest
			.spyOn(authenticatorWithCustomRedirect._jwtVerifier, 'verify')
			.mockRejectedValueOnce(new Error());
		const spyFetchTokensFromCode = jest
			.spyOn(authenticatorWithCustomRedirect, '_fetchTokensFromCode')
			.mockResolvedValueOnce(tokenData);
		const spyGetRedirectResponse = jest
			.spyOn(authenticatorWithCustomRedirect, '_getRedirectResponse')
			.mockResolvedValueOnce({
				status: '302',
			});

		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';
		return expect(authenticatorWithCustomRedirect.handle(request))
			.resolves.toEqual({ status: '302' })
			.then(() => {
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyFetchTokensFromCode).toHaveBeenCalledWith(
					'https://d111111abcdef8.cloudfront.net/custom/login/path',
					'54fe5f4e',
				);
				expect(spyGetRedirectResponse).toHaveBeenCalledWith(
					tokenData,
					'd111111abcdef8.cloudfront.net',
					'/lol',
				);
			});
	});

	test('should fetch and set token if code is present and when csrfProtection is enabled', () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());
		spyGetTokensFromCode.mockResolvedValueOnce(tokenData);
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		authenticator._csrfProtection = {
			nonceSigningSecret: 'foobar',
		};
		const encodedState = Buffer.from(
			JSON.stringify({ redirect_uri: '/lol' }),
		).toString('base64');
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring = `code=54fe5f4e&state=${encodedState}`;
		return expect(authenticator.handle(request))
			.resolves.toEqual({ response: 'toto' })
			.then(() => {
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyGetTokensFromCode).toHaveBeenCalled();
				expect(spyGetRedirectResponse).toHaveBeenCalledWith(
					tokenData,
					'd111111abcdef8.cloudfront.net',
					'/lol',
				);
			});
	});

	test('should redirect to auth domain if unauthenticated and no code', () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());
		return expect(authenticator.handle(getCloudfrontRequest()))
			.resolves.toEqual({
				status: '302',
				headers: {
					location: [
						{
							key: 'Location',
							value:
								'https://my-cognito-domain.auth.us-east-1.amazoncognito.com/authorize?redirect_uri=https%3A%2F%2Fd111111abcdef8.cloudfront.net&response_type=code&client_id=123456789qwertyuiop987abcd&state=%2Flol%253F%253Fparam%253D1',
						},
					],
					'cache-control': [
						{
							key: 'Cache-Control',
							value: 'no-cache, no-store, max-age=0, must-revalidate',
						},
					],
					pragma: [
						{
							key: 'Pragma',
							value: 'no-cache',
						},
					],
				},
			})
			.then(() => {
				expect(spyJwtVerify).toHaveBeenCalled();
			});
	});

	test('should redirect to auth domain if unauthenticated and no code (custom redirect)', () => {
		const authenticatorWithCustomRedirect = new Authenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			parseAuthPath: '/custom/login/path',
		});
		const spyJwtVerify = jest
			.spyOn(authenticatorWithCustomRedirect._jwtVerifier, 'verify')
			.mockRejectedValueOnce(new Error());
		return expect(
			authenticatorWithCustomRedirect.handle(getCloudfrontRequest()),
		)
			.resolves.toEqual({
				status: '302',
				headers: {
					location: [
						{
							key: 'Location',
							value:
								'https://my-cognito-domain.auth.us-east-1.amazoncognito.com/authorize?redirect_uri=https%3A%2F%2Fd111111abcdef8.cloudfront.net%2Fcustom%2Flogin%2Fpath&response_type=code&client_id=123456789qwertyuiop987abcd&state=%2Flol%253F%253Fparam%253D1',
						},
					],
					'cache-control': [
						{
							key: 'Cache-Control',
							value: 'no-cache, no-store, max-age=0, must-revalidate',
						},
					],
					pragma: [
						{
							key: 'Pragma',
							value: 'no-cache',
						},
					],
				},
			})
			.then(() => {
				expect(spyJwtVerify).toHaveBeenCalled();
			});
	});

	test('should redirect to auth domain and clear csrf cookies if unauthenticated and no code', async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());

		authenticator._csrfProtection = {
			nonceSigningSecret: 'foo-bar',
		};
		const response = await authenticator.handle(getCloudfrontRequest());
		expect(response).toMatchObject({
			status: '302',
			headers: {
				'cache-control': [
					{
						key: 'Cache-Control',
						value: 'no-cache, no-store, max-age=0, must-revalidate',
					},
				],
				pragma: [
					{
						key: 'Pragma',
						value: 'no-cache',
					},
				],
			},
		});
		expect(response.headers?.location).toBeDefined();
		const locationHeader = response.headers?.['location'];
		expect(locationHeader).toBeDefined();
		const url = new URL(locationHeader?.[0]?.value ?? '');
		expect(url.origin).toEqual(
			'https://my-cognito-domain.auth.us-east-1.amazoncognito.com',
		);
		expect(url.pathname).toEqual('/authorize');
		expect(url.searchParams.get('redirect_uri')).toEqual(
			'https://d111111abcdef8.cloudfront.net',
		);
		expect(url.searchParams.get('response_type')).toEqual('code');
		expect(url.searchParams.get('client_id')).toEqual(
			'123456789qwertyuiop987abcd',
		);
		expect(url.searchParams.get('state')).toBeDefined();

		// Cookies
		expect(response.headers?.['set-cookie']).toBeDefined();
		const setCookieHeaders = response.headers?.['set-cookie'];
		const cookies =
			setCookieHeaders?.map(
				(h: { key?: string | undefined; value: string }) => h.value,
			) ?? [];
		expect(
			cookies.find((c) => c.match(`.${NONCE_COOKIE_NAME_SUFFIX}=`)),
		).toBeDefined();
		expect(
			cookies.find((c) => c.match(`.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=`)),
		).toBeDefined();
		expect(
			cookies.find((c) => c.match(`.${PKCE_COOKIE_NAME_SUFFIX}=`)),
		).toBeDefined();
	});

	test('should redirect to auth domain with custom return redirect if unauthenticated', async () => {
		const authenticatorWithCustomRedirect = new Authenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			parseAuthPath: '/custom/login/path',
		});
		jest
			.spyOn(authenticatorWithCustomRedirect._jwtVerifier, 'verify')
			.mockRejectedValueOnce(new Error());
		const response = await authenticatorWithCustomRedirect.handle(
			getCloudfrontRequest(),
		);

		expect(response.headers?.location).toBeDefined();
		const locationHeader = response.headers?.location;
		const url = new URL(locationHeader?.[0]?.value ?? '');
		expect(url.searchParams.get('redirect_uri')).toEqual(
			'https://d111111abcdef8.cloudfront.net/custom/login/path',
		);
	});

	test('should revoke tokens and clear cookies if logoutConfiguration is set', () => {
		authenticator._logoutConfiguration = {
			logoutUri: '/logout',
			logoutRedirectUri: 'https://example.com',
		};
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyRevokeTokens.mockResolvedValueOnce(undefined);
		spyClearCookies.mockResolvedValueOnce({ status: '302' });
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.uri = '/logout';
		return expect(authenticator.handle(request))
			.resolves.toEqual(expect.objectContaining({ status: '302' }))
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyRevokeTokens).toHaveBeenCalled();
				expect(spyClearCookies).toHaveBeenCalled();
			});
	});

	test('should clear cookies if logoutConfiguration is set even if user is unauthenticated', async () => {
		authenticator._logoutConfiguration = {
			logoutUri: '/logout',
			logoutRedirectUri: 'https://example.com',
		};
		spyGetTokensFromCookie.mockImplementationOnce(() => {
			throw new Error();
		});
		spyClearCookies.mockResolvedValueOnce({ status: '302' });

		const request = getCloudfrontRequest();
		request.Records[0].cf.request.uri = '/logout';
		return expect(authenticator.handle(request))
			.resolves.toEqual(expect.objectContaining({ status: '302' }))
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyRevokeTokens).not.toHaveBeenCalled();
				expect(spyClearCookies).toHaveBeenCalled();
			});
	});

	describe('_getRedirectResponse', () => {
		test('should handle expected case (relative path with / prefix)', async () => {
			spyJwtVerify.mockReturnValueOnce(
				Promise.resolve(createMockCognitoPayload('toto')),
			);

			const response = await authenticator._getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				'example.com',
				'/subpath/1',
			);

			expect(response.headers?.location).toBeDefined();
			const locationHeader = response.headers?.location;
			expect(locationHeader?.[0]?.value).toEqual(
				'https://example.com/subpath/1',
			);
		});

		test('should handle case where relative path is missing / prefix)', async () => {
			jest.spyOn(authenticator._jwtVerifier, 'verify');
			spyJwtVerify.mockReturnValueOnce(
				Promise.resolve(createMockCognitoPayload('toto')),
			);

			const response = await authenticator._getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				'example.com',
				'subpath/2',
			);

			expect(response.headers?.location).toBeDefined();
			const locationHeader = response.headers?.location;
			expect(locationHeader?.[0]?.value).toEqual(
				'https://example.com/subpath/2',
			);
		});

		test('should redirect to a subpath of the CloudFront domain even if state contains a malicious URL (inc. protocol)', async () => {
			spyJwtVerify.mockReturnValueOnce(
				Promise.resolve(createMockCognitoPayload('toto')),
			);

			const response = await authenticator._getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				'example.com',
				'https://malicious-site.com/phishing',
			);

			expect(response.headers?.location).toBeDefined();
			const locationHeader = response.headers?.location;
			expect(locationHeader?.[0]?.value).toEqual(
				'https://example.com/https://malicious-site.com/phishing',
			);
		});

		test('should redirect to a subpath of the CloudFront domain even if state contains a malicious URL (// no protocol)', async () => {
			spyJwtVerify.mockReturnValueOnce(
				Promise.resolve(createMockCognitoPayload('toto')),
			);

			const response = await authenticator._getRedirectResponse(
				{
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
					idToken: tokenData.id_token,
				},
				'example.com',
				'//malicious-site.com/phishing',
			);

			expect(response.headers?.location).toBeDefined();
			const locationHeader = response.headers?.location;
			expect(locationHeader?.[0]?.value).toEqual(
				'https://example.com//malicious-site.com/phishing',
			);
		});
	});
});

describe('handleSignIn', () => {
	let authenticator: Authenticator;
	let spyGetTokensFromCookie: jest.SpyInstance;
	let spyRedirectToCognito: jest.SpyInstance;
	let spyJwtVerify: jest.SpyInstance;

	beforeEach(() => {
		authenticator = new Authenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			cookieExpirationDays: 365,
			parseAuthPath: 'parseAuth',
		});
		authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
		spyGetTokensFromCookie = jest.spyOn(authenticator, '_getTokensFromCookie');
		spyRedirectToCognito = jest.spyOn(
			authenticator,
			'_getRedirectToCognitoUserPoolResponse',
		);
		spyJwtVerify = jest.spyOn(authenticator._jwtVerifier, 'verify');
	});

	test('should forward request if authenticated', async () => {
		spyJwtVerify.mockReturnValueOnce(
			Promise.resolve({
				token_use: 'id',
				sub: 'test-sub',
				iss: 'test-iss',
				exp: 0,
				iat: 0,
				auth_time: 0,
				jti: 'test-jti',
				origin_jti: 'test-origin-jti',
			}),
		);
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring =
			'redirect_uri=https://example.aws.com';
		const response = await authenticator.handleSignIn(request);
		expect(response.status).toEqual('302');
		expect(response.headers?.location).toBeDefined();
		const locationHeader = response.headers?.location;
		expect(locationHeader?.[0]?.value).toEqual('https://example.aws.com');
	});

	test('should redirect to cognito if refresh token is invalid', () => {
		spyJwtVerify.mockReturnValueOnce(Promise.reject(new Error()));
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyRedirectToCognito.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();
		return expect(authenticator.handleSignIn(request))
			.resolves.toEqual({ response: 'toto' })
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyRedirectToCognito).toHaveBeenCalled();
			});
	});
});

describe('handleParseAuth', () => {
	let authenticator: Authenticator;
	let spyValidateCSRFCookies: jest.SpyInstance;
	let spyGetTokensFromCode: jest.SpyInstance;
	let spyGetRedirectResponse: jest.SpyInstance;

	beforeEach(() => {
		authenticator = new Authenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			cookieExpirationDays: 365,
			parseAuthPath: 'parseAuth',
		});
		authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
		spyValidateCSRFCookies = jest.spyOn(authenticator, '_validateCSRFCookies');
		spyGetTokensFromCode = jest.spyOn(authenticator, '_fetchTokensFromCode');
		spyGetRedirectResponse = jest.spyOn(authenticator, '_getRedirectResponse');
	});

	describe('if code is present', () => {
		test('should redirect successfully if csrfProtection is not enabled', async () => {
			spyGetTokensFromCode.mockReturnValueOnce(
				Promise.resolve({
					idToken: tokenData.id_token,
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
				}),
			);
			spyGetRedirectResponse.mockReturnValueOnce({
				response: 'toto',
			});
			const state = Buffer.from(
				JSON.stringify({
					nonce: 'nonceValue',
					nonceHmac: 'nonceHmacValue',
					pkce: 'pkceValue',
				}),
			).toString('base64');
			const request = getCloudfrontRequest();
			request.Records[0].cf.request.querystring = `code=code&state=${state}`;
			return expect(authenticator.handleParseAuth(request))
				.resolves.toEqual({ response: 'toto' })
				.then(() => {
					expect(spyValidateCSRFCookies).not.toHaveBeenCalled();
					expect(spyGetTokensFromCode).toHaveBeenCalled();
					expect(spyGetRedirectResponse).toHaveBeenCalled();
				});
		});

		test('should redirect successfully after validating CSRF tokens', async () => {
			authenticator._csrfProtection = {
				nonceSigningSecret: 'foo-bar',
			};
			spyValidateCSRFCookies.mockImplementation();
			spyGetTokensFromCode.mockReturnValueOnce(
				Promise.resolve({
					idToken: tokenData.id_token,
					refreshToken: tokenData.refresh_token,
					accessToken: tokenData.access_token,
				}),
			);
			spyGetRedirectResponse.mockReturnValueOnce({
				response: 'toto',
			});
			const state = Buffer.from(
				JSON.stringify({
					nonce: 'nonceValue',
					nonceHmac: 'nonceHmacValue',
					pkce: 'pkceValue',
				}),
			).toString('base64');
			const request = getCloudfrontRequest();
			request.Records[0].cf.request.querystring = `code=code&state=${state}`;
			return expect(authenticator.handleParseAuth(request))
				.resolves.toEqual({ response: 'toto' })
				.then(() => {
					expect(spyValidateCSRFCookies).toHaveBeenCalled();
					expect(spyGetTokensFromCode).toHaveBeenCalled();
					expect(spyGetRedirectResponse).toHaveBeenCalled();
				});
		});
	});

	test('should throw error when parseAuthPath is not set', async () => {
		authenticator._parseAuthPath = '';
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const result: CloudFrontResultResponse =
			await authenticator.handleParseAuth(getCloudfrontRequest());
		expect(result).toEqual({
			status: '400',
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			body: expect.stringContaining('parseAuthPath'),
		});
		expect(spyValidateCSRFCookies).not.toHaveBeenCalled();
		expect(spyGetTokensFromCode).not.toHaveBeenCalled();
		expect(spyGetRedirectResponse).not.toHaveBeenCalled();
	});

	test('should throw if code is absent', async () => {
		spyValidateCSRFCookies.mockImplementationOnce(() =>
			Promise.reject(new Error()),
		);
		const result = await authenticator.handleParseAuth(getCloudfrontRequest());
		expect(result).toEqual(expect.objectContaining({ status: '400' }));
		expect(spyValidateCSRFCookies).not.toHaveBeenCalled();
		expect(spyGetTokensFromCode).not.toHaveBeenCalled();
		expect(spyGetRedirectResponse).not.toHaveBeenCalled();
	});
});

describe('handleRefreshToken', () => {
	let authenticator: Authenticator;
	let spyGetTokensFromCookie: jest.SpyInstance;
	let spyJwtVerify: jest.SpyInstance;
	let spyFetchTokensFromRefreshToken: jest.SpyInstance;
	let spyGetRedirectResponse: jest.SpyInstance;

	beforeEach(() => {
		authenticator = new Authenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			cookieExpirationDays: 365,
		});
		authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
		spyGetTokensFromCookie = jest.spyOn(authenticator, '_getTokensFromCookie');
		spyJwtVerify = jest.spyOn(authenticator._jwtVerifier, 'verify');
		spyFetchTokensFromRefreshToken = jest.spyOn(
			authenticator,
			'_fetchTokensFromRefreshToken',
		);
		spyGetRedirectResponse = jest.spyOn(authenticator, '_getRedirectResponse');
		jest.spyOn(authenticator, '_getRedirectToCognitoUserPoolResponse');
	});

	test('should refresh tokens successfully', async () => {
		const username = 'toto';
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyJwtVerify.mockReturnValueOnce(
			Promise.resolve(createMockCognitoPayload(username)),
		);
		spyFetchTokensFromRefreshToken.mockReturnValueOnce(
			Promise.resolve({
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
			}),
		);
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		return expect(authenticator.handleRefreshToken(getCloudfrontRequest()))
			.resolves.toEqual({ response: 'toto' })
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyFetchTokensFromRefreshToken).toHaveBeenCalled();
				expect(spyGetRedirectResponse).toHaveBeenCalled();
			});
	});

	test('should redirect to cognito user pool if refresh token is invalid', () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyJwtVerify.mockReturnValueOnce(Promise.reject(new Error()));
		return expect(authenticator.handleRefreshToken(getCloudfrontRequest()))
			.resolves.toEqual(expect.objectContaining({ status: '302' }))
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyJwtVerify).toHaveBeenCalled();
				expect(spyFetchTokensFromRefreshToken).not.toHaveBeenCalled();
				expect(spyGetRedirectResponse).not.toHaveBeenCalled();
			});
	});
});

describe('handleSignOut', () => {
	let authenticator: Authenticator;
	let spyGetTokensFromCookie: jest.SpyInstance;
	let spyRevokeTokens: jest.SpyInstance;
	let spyClearCookies: jest.SpyInstance;

	beforeEach(() => {
		authenticator = new Authenticator({
			region: 'us-east-1',
			userPoolId: 'us-east-1_abcdef123',
			userPoolAppId: '123456789qwertyuiop987abcd',
			userPoolDomain: 'my-cognito-domain.auth.us-east-1.amazoncognito.com',
			cookieExpirationDays: 365,
		});
		authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
		spyGetTokensFromCookie = jest.spyOn(authenticator, '_getTokensFromCookie');
		spyRevokeTokens = jest.spyOn(authenticator, '_revokeTokens');
		spyClearCookies = jest.spyOn(authenticator, '_clearCookies');
	});

	test('should revoke tokens and clear cookies successfully', async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyRevokeTokens.mockResolvedValueOnce(undefined);
		spyClearCookies.mockResolvedValueOnce({ status: '302' });
		return expect(authenticator.handleSignOut(getCloudfrontRequest()))
			.resolves.toEqual(expect.objectContaining({ status: '302' }))
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyRevokeTokens).toHaveBeenCalled();
				expect(spyClearCookies).toHaveBeenCalled();
			});
	});

	test('should clear cookies successfully even if tokens cannot be revoked', async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyRevokeTokens.mockReturnValueOnce(Promise.reject(new Error()));
		spyClearCookies.mockResolvedValueOnce({ status: '302' });
		return expect(authenticator.handleSignOut(getCloudfrontRequest()))
			.resolves.toEqual(expect.objectContaining({ status: '302' }))
			.then(() => {
				expect(spyGetTokensFromCookie).toHaveBeenCalled();
				expect(spyRevokeTokens).toHaveBeenCalled();
				expect(spyClearCookies).toHaveBeenCalled();
			});
	});
});

const jwksData = {
	keys: [
		{
			kid: '1234example=',
			alg: 'RS256',
			kty: 'RSA',
			e: 'AQAB',
			n: '1234567890',
			use: 'sig',
		},
		{
			kid: '5678example=',
			alg: 'RS256',
			kty: 'RSA',
			e: 'AQAB',
			n: '987654321',
			use: 'sig',
		},
	],
};

const tokenData = {
	access_token: 'eyJz9sdfsdfsdfsd',
	refresh_token: 'dn43ud8uj32nk2je',
	id_token: 'dmcxd329ujdmkemkd349r',
	token_type: 'Bearer' as const,
	expires_in: 3600,
};

const getCloudfrontRequest = () =>
	({
		Records: [
			{
				cf: {
					config: {
						distributionDomainName: 'd123.cloudfront.net',
						distributionId: 'EDFDVBD6EXAMPLE',
						eventType: 'viewer-request' as const,
						requestId:
							'MRVMF7KydIvxMWfJIglgwHQwZsbG2IhRJ07sn9AkKUFSHS9EXAMPLE==',
					},
					request: {
						body: {
							action: 'read-only' as const,
							data: 'eyJ1c2VybmFtZSI6IkxhbWJkYUBFZGdlIiwiY29tbWVudCI6IlRoaXMgaXMgcmVxdWVzdCBib2R5In0=',
							encoding: 'base64' as const,
							inputTruncated: false,
						},
						clientIp: '2001:0db8:85a3:0:0:8a2e:0370:7334',
						querystring: '?param=1',
						uri: '/lol',
						method: 'GET',
						headers: {
							host: [
								{
									key: 'Host',
									value: 'd111111abcdef8.cloudfront.net',
								},
							],
							'user-agent': [
								{
									key: 'User-Agent',
									value: 'curl/7.51.0',
								},
							],
							cookie: [
								{
									key: 'cookie',
									value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.toto.idToken=${tokenData.access_token};`,
								},
							],
						},
						origin: {
							custom: {
								customHeaders: {
									'my-origin-custom-header': [
										{
											key: 'My-Origin-Custom-Header',
											value: 'Test',
										},
									],
								},
								domainName: 'example.com',
								keepaliveTimeout: 5,
								path: '/custom_path',
								port: 443,
								protocol: 'https' as const,
								readTimeout: 5,
								sslProtocols: ['TLSv1', 'TLSv1.1'],
							},
						},
					},
				},
			},
		],
	}) satisfies CloudFrontRequestEvent;

// Helper to create a minimal valid Cognito JWT payload for testing
const createMockCognitoPayload = (username?: string) => ({
	token_use: 'id' as const,
	sub: 'test-sub',
	iss: 'test-iss',
	exp: 0,
	iat: 0,
	auth_time: 0,
	jti: 'test-jti',
	origin_jti: 'test-origin-jti',
	aud: 'test-aud',
	at_hash: 'test-at-hash',
	'cognito:username': username || 'test-user',
	email_verified: false,
	phone_number_verified: false,
	identities: [],
	'cognito:roles': [],
	'cognito:preferred_role': 'test-role',
});
