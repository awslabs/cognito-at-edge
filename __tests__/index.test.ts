/* eslint-disable @typescript-eslint/ban-ts-comment */
import axios from 'axios';
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

const TEST_DATE = new Date('2017-01-01T00:00:00.000Z');

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
		jest.useFakeTimers();
		jest.setSystemTime(TEST_DATE);

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
		jest.useRealTimers();
		jest.restoreAllMocks();
	});

	test('should fetch token', async () => {
		jest.spyOn(axios, 'request').mockResolvedValue({ data: tokenData });

		const res = await authenticator._fetchTokensFromCode(
			'htt://redirect',
			'AUTH_CODE',
		);

		expect(res).toMatchObject({
			refreshToken: tokenData.refresh_token,
			accessToken: tokenData.access_token,
			idToken: tokenData.id_token,
		});
	});

	describe('should refresh tokens', () => {
		test('and update refresh token when new refresh token returned', async () => {
			jest.spyOn(axios, 'request').mockResolvedValue({ data: tokenData });

			const res = await authenticator._fetchTokensFromRefreshToken(
				'htt://redirect',
				'REFRESH_TOKEN',
			);

			expect(res).toMatchObject({
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
				idToken: tokenData.id_token,
			});
		});

		test('and keep existing refresh token when no new refresh token returned', async () => {
			jest
				.spyOn(axios, 'request')
				.mockResolvedValue({ data: tokenDataWithoutRefreshToken });

			const res = await authenticator._fetchTokensFromRefreshToken(
				'htt://redirect',
				'REFRESH_TOKEN',
			);

			expect(res).toMatchObject({
				refreshToken: 'REFRESH_TOKEN',
				accessToken: tokenDataWithoutRefreshToken.access_token,
				idToken: tokenDataWithoutRefreshToken.id_token,
			});
		});
	});

	test('should throw if unable to fetch token', async () => {
		const unexpectedError = new Error('Unexpected error');
		jest.spyOn(axios, 'request').mockRejectedValue(unexpectedError);

		await expect(() =>
			authenticator._fetchTokensFromCode('htt://redirect', 'AUTH_CODE'),
		).rejects.toThrow(unexpectedError);
	});

	test('should getRedirectResponse', async () => {
		const username = 'toto';
		const domain = 'example.com';
		const path = '/test';
		const spyJwtVerify = jest
			.spyOn(authenticator._jwtVerifier, 'verify')
			.mockResolvedValueOnce(createMockCognitoPayload(username));

		const expectedDefaultExpiration = new Date(TEST_DATE);
		expectedDefaultExpiration.setDate(
			expectedDefaultExpiration.getDate() + 365,
		);
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
		expect(response.headers?.['set-cookie']).toStrictEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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

		const expectedDefaultExpiration = new Date(TEST_DATE);
		expectedDefaultExpiration.setDate(
			expectedDefaultExpiration.getDate() + 365,
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
		expect(response.headers?.['set-cookie']).toStrictEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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

		const expectedDefaultExpiration = new Date(TEST_DATE);
		expectedDefaultExpiration.setDate(
			expectedDefaultExpiration.getDate() + 365,
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
		expect(response.headers?.['set-cookie']).toStrictEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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

		const expectedDefaultExpiration = new Date(TEST_DATE);
		expectedDefaultExpiration.setDate(
			expectedDefaultExpiration.getDate() + 365,
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
		expect(response.headers?.['set-cookie']).toStrictEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly; SameSite=Strict`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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

		const expectedDefaultExpiration = new Date(TEST_DATE);
		expectedDefaultExpiration.setDate(
			expectedDefaultExpiration.getDate() + 365,
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
		expect(response.headers?.['set-cookie']).toStrictEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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
		const expectedDefaultExpiration = new Date(TEST_DATE);
		expectedDefaultExpiration.setDate(
			expectedDefaultExpiration.getDate() + 365,
		);

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
		expect(response.headers?.['set-cookie']).toStrictEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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

		const expectedAccessTokenExpiration = new Date(TEST_DATE);
		expectedAccessTokenExpiration.setDate(
			expectedAccessTokenExpiration.getDate() + 2,
		);

		const expectedDefaultExpiration = new Date(TEST_DATE);
		expectedDefaultExpiration.setDate(
			expectedDefaultExpiration.getDate() + 365,
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
		expect(response.headers?.['set-cookie']).toStrictEqual(
			expect.arrayContaining([
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.accessToken=${tokenData.access_token}; Domain=${domain}; Path=/foo; Expires=${expectedAccessTokenExpiration.toUTCString()}; Secure; SameSite=Lax`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.refreshToken=${tokenData.refresh_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.tokenScopesString=phone%20email%20profile%20openid%20aws.cognito.signin.user.admin; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${username}.idToken=${tokenData.id_token}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.LastAuthUser=${username}; Domain=${domain}; Path=${cookiePath}; Expires=${expectedDefaultExpiration.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${PKCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure; HttpOnly`,
				},
				{
					key: 'Set-Cookie',
					value: `CognitoIdentityServiceProvider.123456789qwertyuiop987abcd.${NONCE_HMAC_COOKIE_NAME_SUFFIX}=; Path=${cookiePath}; Expires=${TEST_DATE.toUTCString()}; Secure; HttpOnly`,
				},
			]),
		);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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

		test('should throw error when nonce cookie is not present', () => {
			const request = buildRequest({ nonce: 'nonce-value' }, {});
			expect(() => {
				authenticator._validateCSRFCookies(request);
			}).toThrow(
				"Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).",
			);
		});

		test('should throw error when nonce cookie is different than the one encoded in state', () => {
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

		test('should throw error when pkce cookie is absent', () => {
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

		test('should throw error when calculated Hmac is different than the one stored in the cookie', async () => {
			const csrfModule = await import('../src/util/csrf');
			jest
				.spyOn(csrfModule, 'signNonce')
				.mockReturnValue('nonce-hmac-value-different');

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
		test('should verify tokens and clear cookies', async () => {
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
			expect(response).toStrictEqual(
				expect.objectContaining({
					status: '302',
				}),
			);
			expect(response.headers?.['set-cookie'].length).toBe(5);
		});

		test('should clear cookies even if tokens cannot be verified', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockRejectedValueOnce(new Error());
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const tokens = {
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
			};
			const request = getCloudfrontRequest();
			const numCookiesToBeCleared =
				request.Records[0].cf.request.headers['cookie'].length || 0;
			const response = await authenticator._clearCookies(request, tokens);
			expect(response).toStrictEqual(
				expect.objectContaining({
					status: '302',
				}),
			);
			expect(response.headers?.['set-cookie'].length).toBe(
				numCookiesToBeCleared,
			);
		});

		test('should clear cookies and redirect to logoutRedirectUri', async () => {
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
			expect(response).toStrictEqual(
				expect.objectContaining({ status: '302' }),
			);
			expect(response.headers?.['location']?.[0]?.value).toStrictEqual(
				'https://foobar.com',
			);
		});

		test('should clear cookies and redirect to redirect_uri query param', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockResolvedValueOnce(createMockCognitoPayload());
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const request = getCloudfrontRequest();
			request.Records[0].cf.request.querystring =
				'redirect_uri=https://foobar.com';
			const response = await authenticator._clearCookies(request);
			expect(response).toStrictEqual(
				expect.objectContaining({ status: '302' }),
			);
			expect(response.headers?.['location']?.[0]?.value).toStrictEqual(
				'https://foobar.com',
			);
		});

		test('should clear cookies and redirect to cf domain', async () => {
			jest
				.spyOn(authenticator._jwtVerifier, 'verify')
				.mockResolvedValueOnce(createMockCognitoPayload());
			authenticator._jwtVerifier.cacheJwks(jwksData, 'us-east-1_abcdef123');
			const request = getCloudfrontRequest();
			const response = await authenticator._clearCookies(request);
			expect(response).toStrictEqual(
				expect.objectContaining({ status: '302' }),
			);
			expect(response.headers?.['location']?.[0]?.value).toStrictEqual(
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
		jest.useFakeTimers();
		jest.setSystemTime(TEST_DATE);

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

	afterEach(() => {
		jest.useRealTimers();
		jest.restoreAllMocks();
	});

	test('should forward request if authenticated', async () => {
		spyJwtVerify.mockResolvedValueOnce({
			token_use: 'id',
			sub: 'test-sub',
			iss: 'test-iss',
			exp: 0,
			iat: 0,
			auth_time: 0,
			jti: 'test-jti',
			origin_jti: 'test-origin-jti',
		});

		const result = await authenticator.handle(getCloudfrontRequest());

		expect(result).toStrictEqual(getCloudfrontRequest().Records[0].cf.request);
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
	});

	test('should fetch with refresh token if available', async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyFetchTokensFromRefreshToken.mockResolvedValueOnce(tokenData);
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';

		const result = await authenticator.handle(request);

		expect(result).toStrictEqual({ response: 'toto' });
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
		expect(spyFetchTokensFromRefreshToken).toHaveBeenCalledTimes(1);
		expect(spyGetRedirectResponse).toHaveBeenCalledWith(
			tokenData,
			'd111111abcdef8.cloudfront.net',
			'/lol',
		);
	});

	test('should redirect to cognito if refresh token is invalid', async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyFetchTokensFromRefreshToken.mockRejectedValueOnce(new Error());
		spyGetRedirectToCognitoUserPoolResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();

		const result = await authenticator.handle(request);

		expect(result).toStrictEqual({ response: 'toto' });
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
		expect(spyFetchTokensFromRefreshToken).toHaveBeenCalledTimes(1);
	});

	test('should fetch and set token if code is present', async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());
		spyGetTokensFromCode.mockResolvedValueOnce(tokenData);
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring = 'code=54fe5f4e&state=/lol';

		const result = await authenticator.handle(request);

		expect(result).toStrictEqual({ response: 'toto' });
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
		expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1);
		expect(spyGetRedirectResponse).toHaveBeenCalledWith(
			tokenData,
			'd111111abcdef8.cloudfront.net',
			'/lol',
		);
	});

	test('should fetch and set token if code is present (custom redirect)', async () => {
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

		const result = await authenticatorWithCustomRedirect.handle(request);

		expect(result).toStrictEqual({ status: '302' });
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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

	test('should fetch and set token if code is present and when csrfProtection is enabled', async () => {
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

		const result = await authenticator.handle(request);

		expect(result).toStrictEqual({ response: 'toto' });
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
		expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1);
		expect(spyGetRedirectResponse).toHaveBeenCalledWith(
			tokenData,
			'd111111abcdef8.cloudfront.net',
			'/lol',
		);
	});

	test('should redirect to auth domain if unauthenticated and no code', async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());

		const result = await authenticator.handle(getCloudfrontRequest());

		expect(result).toStrictEqual({
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
		});
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
	});

	test('should redirect to auth domain if unauthenticated and no code (custom redirect)', async () => {
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

		const result = await authenticatorWithCustomRedirect.handle(
			getCloudfrontRequest(),
		);

		expect(result).toStrictEqual({
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
		});
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
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
		expect(url.origin).toStrictEqual(
			'https://my-cognito-domain.auth.us-east-1.amazoncognito.com',
		);
		expect(url.pathname).toStrictEqual('/authorize');
		expect(url.searchParams.get('redirect_uri')).toStrictEqual(
			'https://d111111abcdef8.cloudfront.net',
		);
		expect(url.searchParams.get('response_type')).toStrictEqual('code');
		expect(url.searchParams.get('client_id')).toStrictEqual(
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
		expect(url.searchParams.get('redirect_uri')).toStrictEqual(
			'https://d111111abcdef8.cloudfront.net/custom/login/path',
		);
	});

	test('should revoke tokens and clear cookies if logoutConfiguration is set', async () => {
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

		const result = await authenticator.handle(request);

		expect(result).toStrictEqual(expect.objectContaining({ status: '302' }));
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyRevokeTokens).toHaveBeenCalledTimes(1);
		expect(spyClearCookies).toHaveBeenCalledTimes(1);
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

		const result = await authenticator.handle(request);

		expect(result).toStrictEqual(expect.objectContaining({ status: '302' }));
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyRevokeTokens).not.toHaveBeenCalledTimes(1);
		expect(spyClearCookies).toHaveBeenCalledTimes(1);
	});

	describe('_getRedirectResponse', () => {
		test('should handle expected case (relative path with / prefix)', async () => {
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload('toto'));

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
			expect(locationHeader?.[0]?.value).toStrictEqual(
				'https://example.com/subpath/1',
			);
		});

		test('should handle case where relative path is missing / prefix)', async () => {
			jest.spyOn(authenticator._jwtVerifier, 'verify');
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload('toto'));

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
			expect(locationHeader?.[0]?.value).toStrictEqual(
				'https://example.com/subpath/2',
			);
		});

		test('should redirect to a subpath of the CloudFront domain even if state contains a malicious URL (inc. protocol)', async () => {
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload('toto'));

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
			expect(locationHeader?.[0]?.value).toStrictEqual(
				'https://example.com/https://malicious-site.com/phishing',
			);
		});

		test('should redirect to a subpath of the CloudFront domain even if state contains a malicious URL (// no protocol)', async () => {
			spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload('toto'));

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
			expect(locationHeader?.[0]?.value).toStrictEqual(
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
		jest.useFakeTimers();
		jest.setSystemTime(TEST_DATE);

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

	afterEach(() => {
		jest.useRealTimers();
		jest.restoreAllMocks();
	});

	test('should forward request if authenticated', async () => {
		spyJwtVerify.mockResolvedValueOnce({
			token_use: 'id',
			sub: 'test-sub',
			iss: 'test-iss',
			exp: 0,
			iat: 0,
			auth_time: 0,
			jti: 'test-jti',
			origin_jti: 'test-origin-jti',
		});
		const request = getCloudfrontRequest();
		request.Records[0].cf.request.querystring =
			'redirect_uri=https://example.aws.com';
		const response = await authenticator.handleSignIn(request);
		expect(response.status).toStrictEqual('302');
		expect(response.headers?.location).toBeDefined();
		const locationHeader = response.headers?.location;
		expect(locationHeader?.[0]?.value).toStrictEqual('https://example.aws.com');
	});

	test('should redirect to cognito if refresh token is invalid', async () => {
		spyJwtVerify.mockRejectedValueOnce(new Error());
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyRedirectToCognito.mockReturnValueOnce({
			response: 'toto',
		});
		const request = getCloudfrontRequest();

		const result = await authenticator.handleSignIn(request);

		expect(result).toStrictEqual({ response: 'toto' });
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
		expect(spyRedirectToCognito).toHaveBeenCalledTimes(1);
	});
});

describe('handleParseAuth', () => {
	let authenticator: Authenticator;
	let spyValidateCSRFCookies: jest.SpyInstance;
	let spyGetTokensFromCode: jest.SpyInstance;
	let spyGetRedirectResponse: jest.SpyInstance;

	beforeEach(() => {
		jest.useFakeTimers();
		jest.setSystemTime(TEST_DATE);

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

	afterEach(() => {
		jest.useRealTimers();
		jest.restoreAllMocks();
	});

	describe('if code is present', () => {
		test('should redirect successfully if csrfProtection is not enabled', async () => {
			spyGetTokensFromCode.mockResolvedValueOnce({
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
			});
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

			const result = await authenticator.handleParseAuth(request);

			expect(result).toStrictEqual({ response: 'toto' });
			expect(spyValidateCSRFCookies).not.toHaveBeenCalledTimes(1);
			expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1);
			expect(spyGetRedirectResponse).toHaveBeenCalledTimes(1);
		});

		test('should redirect successfully after validating CSRF tokens', async () => {
			authenticator._csrfProtection = {
				nonceSigningSecret: 'foo-bar',
			};
			spyValidateCSRFCookies.mockImplementation();
			spyGetTokensFromCode.mockResolvedValueOnce({
				idToken: tokenData.id_token,
				refreshToken: tokenData.refresh_token,
				accessToken: tokenData.access_token,
			});
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

			const result = await authenticator.handleParseAuth(request);

			expect(result).toStrictEqual({ response: 'toto' });
			expect(spyValidateCSRFCookies).toHaveBeenCalledTimes(1);
			expect(spyGetTokensFromCode).toHaveBeenCalledTimes(1);
			expect(spyGetRedirectResponse).toHaveBeenCalledTimes(1);
		});
	});

	test('should throw error when parseAuthPath is not set', async () => {
		authenticator._parseAuthPath = '';
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});
		const result: CloudFrontResultResponse =
			await authenticator.handleParseAuth(getCloudfrontRequest());
		expect(result).toStrictEqual({
			status: '400',
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			body: expect.stringContaining('parseAuthPath'),
		});
		expect(spyValidateCSRFCookies).not.toHaveBeenCalledTimes(1);
		expect(spyGetTokensFromCode).not.toHaveBeenCalledTimes(1);
		expect(spyGetRedirectResponse).not.toHaveBeenCalledTimes(1);
	});

	test('should throw if code is absent', async () => {
		spyValidateCSRFCookies.mockRejectedValueOnce(new Error());
		const result = await authenticator.handleParseAuth(getCloudfrontRequest());
		expect(result).toStrictEqual(expect.objectContaining({ status: '400' }));
		expect(spyValidateCSRFCookies).not.toHaveBeenCalledTimes(1);
		expect(spyGetTokensFromCode).not.toHaveBeenCalledTimes(1);
		expect(spyGetRedirectResponse).not.toHaveBeenCalledTimes(1);
	});
});

describe('handleRefreshToken', () => {
	let authenticator: Authenticator;
	let spyGetTokensFromCookie: jest.SpyInstance;
	let spyJwtVerify: jest.SpyInstance;
	let spyFetchTokensFromRefreshToken: jest.SpyInstance;
	let spyGetRedirectResponse: jest.SpyInstance;

	beforeEach(() => {
		jest.useFakeTimers();
		jest.setSystemTime(TEST_DATE);

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

	afterEach(() => {
		jest.useRealTimers();
		jest.restoreAllMocks();
	});

	test('should refresh tokens successfully', async () => {
		const username = 'toto';
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyJwtVerify.mockResolvedValueOnce(createMockCognitoPayload(username));
		spyFetchTokensFromRefreshToken.mockResolvedValueOnce({
			idToken: tokenData.id_token,
			refreshToken: tokenData.refresh_token,
			accessToken: tokenData.access_token,
		});
		spyGetRedirectResponse.mockReturnValueOnce({
			response: 'toto',
		});

		const result = await authenticator.handleRefreshToken(
			getCloudfrontRequest(),
		);

		expect(result).toStrictEqual({ response: 'toto' });
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
		expect(spyFetchTokensFromRefreshToken).toHaveBeenCalledTimes(1);
		expect(spyGetRedirectResponse).toHaveBeenCalledTimes(1);
	});

	test('should redirect to cognito user pool if refresh token is invalid', async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyJwtVerify.mockRejectedValueOnce(new Error());

		const result = await authenticator.handleRefreshToken(
			getCloudfrontRequest(),
		);

		expect(result).toStrictEqual(expect.objectContaining({ status: '302' }));
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyJwtVerify).toHaveBeenCalledTimes(1);
		expect(spyFetchTokensFromRefreshToken).not.toHaveBeenCalledTimes(1);
		expect(spyGetRedirectResponse).not.toHaveBeenCalledTimes(1);
	});
});

describe('handleSignOut', () => {
	let authenticator: Authenticator;
	let spyGetTokensFromCookie: jest.SpyInstance;
	let spyRevokeTokens: jest.SpyInstance;
	let spyClearCookies: jest.SpyInstance;

	beforeEach(() => {
		jest.useFakeTimers();
		jest.setSystemTime(TEST_DATE);

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

	afterEach(() => {
		jest.useRealTimers();
		jest.restoreAllMocks();
	});

	test('should revoke tokens and clear cookies successfully', async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyRevokeTokens.mockResolvedValueOnce(undefined);
		spyClearCookies.mockResolvedValueOnce({ status: '302' });

		const result = await authenticator.handleSignOut(getCloudfrontRequest());

		expect(result).toStrictEqual(expect.objectContaining({ status: '302' }));
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyRevokeTokens).toHaveBeenCalledTimes(1);
		expect(spyClearCookies).toHaveBeenCalledTimes(1);
	});

	test('should clear cookies successfully even if tokens cannot be revoked', async () => {
		spyGetTokensFromCookie.mockReturnValueOnce({
			refreshToken: tokenData.refresh_token,
		});
		spyRevokeTokens.mockRejectedValueOnce(new Error());
		spyClearCookies.mockResolvedValueOnce({ status: '302' });

		const result = await authenticator.handleSignOut(getCloudfrontRequest());

		expect(result).toStrictEqual(expect.objectContaining({ status: '302' }));
		expect(spyGetTokensFromCookie).toHaveBeenCalledTimes(1);
		expect(spyRevokeTokens).toHaveBeenCalledTimes(1);
		expect(spyClearCookies).toHaveBeenCalledTimes(1);
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

const tokenDataWithoutRefreshToken = {
	access_token: 'eyJz9sdfsdfsdfsdfsd',
	id_token: 'dmcxd329ujdmkemkd349r',
	token_type: 'Bearer',
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
