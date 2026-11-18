import { createHash, generateKeyPairSync, sign, webcrypto } from 'crypto';
import type { KeyObject } from 'crypto';
import { createContext, runInContext } from 'vm';

interface Settings {
	[name: string]: string | number | boolean;
}
interface BuildModule {
	buildFunction: (settings: Settings) => string;
	assertSupported: (code: string) => void;
	MAX_FUNCTION_BYTES: number;
}
interface Value {
	value: string;
	attributes?: string;
}
interface CffRequest {
	method: string;
	uri: string;
	querystring: Record<string, Value>;
	headers: Record<string, Value>;
	cookies: Record<string, Value>;
}
interface CffResponse {
	statusCode: number;
	statusDescription: string;
	headers: Record<string, Value>;
	cookies?: Record<string, Value>;
	body?: string;
}
type CffResult = CffRequest | CffResponse;
interface FetchOptions {
	originId: string;
	method: string;
	headers: Record<string, string>;
	body: string;
	includeBody: boolean;
}
interface FetchAnswer {
	status: number;
	body: unknown;
}
type FetchFake = (path: string, options: FetchOptions) => FetchAnswer;

const { buildFunction, assertSupported, MAX_FUNCTION_BYTES } =
	jest.requireActual<BuildModule>('../../cloudfront-functions/build.js');

const REGION = 'us-east-1';
const POOL_ID = 'us-east-1_AbCdEfGhI';
const CLIENT_ID = '1234567890abcdefghijklmnop';
const DOMAIN = 'example-prefix.auth.us-east-1.amazoncognito.com';
const HOST = 'd111111abcdef8.cloudfront.net';
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${POOL_ID}`;
const BASE = `CognitoIdentityServiceProvider.${CLIENT_ID}`;
const STATE_COOKIE = `${BASE}.state`;
const KID = 'test-kid';
const SETTINGS: Settings = {
	region: REGION,
	userPoolId: POOL_ID,
	userPoolAppId: CLIENT_ID,
	userPoolDomain: DOMAIN,
	cognitoOriginId: 'cognito',
	logoutPath: '/logout',
	cognitoLogout: true,
	httpOnly: true,
	sameSite: 'Lax',
};

const JWKS_SETTINGS: Settings = { ...SETTINGS, jwksOriginId: 'cognito-idp' };
const JWKS_PATH = `/${POOL_ID}/.well-known/jwks.json`;

const poolKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
const poolJwk = poolKey.publicKey.export({ format: 'jwk' });

function now() {
	return Math.floor(Date.now() / 1000);
}

function b64url(value: string) {
	return Buffer.from(value).toString('base64url');
}

function jwt(
	claims: Record<string, unknown>,
	options: { key?: KeyObject; kid?: string; alg?: string } = {},
) {
	const header = b64url(
		JSON.stringify({ alg: options.alg || 'RS256', kid: options.kid || KID }),
	);
	const payload = b64url(JSON.stringify(claims));
	const signature = sign(
		'sha256',
		Buffer.from(`${header}.${payload}`),
		options.key || poolKey.privateKey,
	).toString('base64url');
	return `${header}.${payload}.${signature}`;
}

function idToken(claims: Record<string, unknown> = {}, options = {}) {
	return jwt(
		{
			iss: ISSUER,
			aud: CLIENT_ID,
			token_use: 'id',
			'cognito:username': 'alice',
			exp: now() + 300,
			...claims,
		},
		options,
	);
}

function accessToken(claims: Record<string, unknown> = {}) {
	return jwt({
		iss: ISSUER,
		client_id: CLIENT_ID,
		token_use: 'access',
		username: 'alice',
		exp: now() + 300,
		...claims,
	});
}

function request(
	uri: string,
	cookies: Record<string, string> = {},
	query: Record<string, string> = {},
): CffRequest {
	const toValues = (map: Record<string, string>) =>
		Object.fromEntries(
			Object.entries(map).map(([name, value]) => [name, { value }]),
		);
	return {
		method: 'GET',
		uri,
		querystring: toValues(query),
		headers: { host: { value: HOST } },
		cookies: toValues(cookies),
	};
}

function userCookies(tokens: {
	id?: string;
	access?: string;
	refresh?: string;
}) {
	const cookies: Record<string, string> = {
		[`${BASE}.LastAuthUser`]: 'alice',
	};
	if (tokens.id) cookies[`${BASE}.alice.idToken`] = tokens.id;
	if (tokens.access) cookies[`${BASE}.alice.accessToken`] = tokens.access;
	if (tokens.refresh) cookies[`${BASE}.alice.refreshToken`] = tokens.refresh;
	return cookies;
}

/**
 * Runs the generated function like CloudFront does: one network call per invocation, and
 * the call throws once WebCrypto ran (the runtime forbids a call after a non-deterministic
 * crypto operation).
 */
function runtime(settings: Settings = SETTINGS) {
	const code = buildFunction(settings).replace(
		"import cf from 'cloudfront';",
		'',
	);
	const calls: {
		path: string;
		options: FetchOptions;
		form: URLSearchParams;
	}[] = [];
	const kvs: Record<string, string> = {
		[`jwk.${KID}`]: JSON.stringify({ n: poolJwk.n, e: poolJwk.e }),
	};
	let webcryptoUsed = false;
	let answer: FetchFake = () => ({ status: 500, body: {} });
	const cf = {
		kvs: () => ({
			get: (key: string) =>
				key in kvs
					? Promise.resolve(kvs[key])
					: Promise.reject(new Error('KeyNotFound')),
		}),
		fetch: (path: string, options: FetchOptions) => {
			if (calls.length > 0) throw new Error('second network call');
			if (webcryptoUsed) throw new Error('network call after WebCrypto');
			calls.push({ path, options, form: new URLSearchParams(options.body) });
			const { status, body } = answer(path, options);
			return Promise.resolve({
				ok: status >= 200 && status < 300,
				status,
				text: () =>
					Promise.resolve(
						typeof body === 'string' ? body : JSON.stringify(body),
					),
			});
		},
	};
	const fakeRequire = (name: string): unknown => {
		if (name === 'crypto') return { createHash };
		if (name === 'webcrypto') {
			webcryptoUsed = true;
			return webcrypto;
		}
		throw new Error(`module ${name} is not available`);
	};
	const context = createContext({
		cf,
		require: fakeRequire,
		Buffer,
		Uint8Array,
	});
	const handler = runInContext(`${code}\nhandler;`, context) as (event: {
		request: CffRequest;
	}) => Promise<CffResult>;
	return {
		calls,
		kvs,
		answer: (fake: FetchFake) => {
			answer = fake;
		},
		fail: (name: string) => {
			answer = () => {
				const error = new Error('The request could not be completed');
				error.name = name;
				throw error;
			};
		},
		handle: (req: CffRequest) => handler({ request: req }),
	};
}

function asResponse(result: CffResult): CffResponse {
	if (!('statusCode' in result)) throw new Error('expected a response');
	return result;
}

function location(result: CffResult) {
	return new URL(asResponse(result).headers.location.value);
}

function stateCookie(state: string, verifier: string, back: string) {
	return { [STATE_COOKIE]: `${state}.${verifier}.${b64url(back)}` };
}

describe('cloudfront functions build', () => {
	test('stays under the CloudFront Functions size limit', () => {
		expect(Buffer.byteLength(buildFunction(JWKS_SETTINGS))).toBeLessThan(
			MAX_FUNCTION_BYTES,
		);
	});

	test('embeds the settings with their defaults', () => {
		const code = buildFunction({ ...SETTINGS, logoutPath: '' });

		expect(code).toContain(`"userPoolAppId":"${CLIENT_ID}"`);
		expect(code).toContain('"parseAuthPath":"/parseauth"');
		expect(code).not.toContain('__CONFIG__');
	});

	test.each([
		[{ region: '' }, 'Expected settings.region to be a non-empty string'],
		[{ tokenUse: 'refresh' }, 'Expected settings.tokenUse to be id || access'],
		[{ parseAuthPath: 'parseauth' }, 'Expected settings.parseAuthPath'],
		[{ parseAuthPath: '/logout' }, 'differ from logoutPath'],
		[{ sameSite: 'lax' }, 'Expected settings.sameSite'],
		[{ cookieExpirationDays: 0 }, 'Expected settings.cookieExpirationDays'],
	])('rejects invalid settings %j', (override, message) => {
		expect(() => buildFunction({ ...SETTINGS, ...override })).toThrow(message);
	});

	test.each([
		['for (const a of b) {}', 'for...of'],
		['const a = b?.c;', 'optional chaining'],
		['const a = { ...b };', 'spread'],
		['f(await g());', 'await inside call arguments'],
	])('rejects syntax the runtime does not run: %s', (code, name) => {
		expect(() => {
			assertSupported(code);
		}).toThrow(name);
	});
});

describe('cloudfront functions viewer request', () => {
	test('forwards a request with a valid id token, without a network call', async () => {
		const rt = runtime();
		const req = request('/page', userCookies({ id: idToken() }));

		await expect(rt.handle(req)).resolves.toBe(req);
		expect(rt.calls).toHaveLength(0);
	});

	test('redirects to the hosted UI with state and a PKCE challenge', async () => {
		const rt = runtime();
		const result = asResponse(await rt.handle(request('/a/b', {}, { x: '1' })));
		const url = location(result);
		const [state, verifier, back] = (
			result.cookies?.[STATE_COOKIE]?.value || ''
		).split('.');

		expect(result.statusCode).toBe(302);
		expect(url.origin + url.pathname).toBe(
			`https://${DOMAIN}/oauth2/authorize`,
		);
		expect(Object.fromEntries(url.searchParams)).toStrictEqual({
			response_type: 'code',
			client_id: CLIENT_ID,
			redirect_uri: `https://${HOST}/parseauth`,
			state,
			code_challenge: createHash('sha256').update(verifier).digest('base64url'),
			code_challenge_method: 'S256',
		});
		expect(Buffer.from(back, 'base64url').toString()).toBe('/a/b?x=1');
		expect(result.cookies?.[STATE_COOKIE]?.attributes).toContain('HttpOnly');
		expect(rt.calls).toHaveLength(0);
	});

	test.each([
		['a forged signature', idToken({}, { key: otherKey.privateKey })],
		['a wrong audience', idToken({ aud: 'another-client' })],
		['a wrong issuer', idToken({ iss: 'https://issuer.example.com' })],
		['an access token in the id token cookie', accessToken()],
		['an unknown key id', idToken({}, { kid: 'rotated-away' })],
		['alg HS256', idToken({}, { alg: 'HS256' })],
		['a malformed token', 'not-a-jwt'],
		['an expired token and no refresh token', idToken({ exp: now() - 10 })],
	])('redirects to the hosted UI for %s', async (_name, token) => {
		const rt = runtime();
		const result = await rt.handle(
			request('/page', userCookies({ id: token })),
		);

		expect(location(result).pathname).toBe('/oauth2/authorize');
		expect(rt.calls).toHaveLength(0);
	});

	test('accepts a valid access token when tokenUse is access', async () => {
		const rt = runtime({ ...SETTINGS, tokenUse: 'access' });
		const req = request('/page', userCookies({ access: accessToken() }));

		await expect(rt.handle(req)).resolves.toBe(req);
	});

	test('finds the token cookies without LastAuthUser', async () => {
		const rt = runtime();
		const req = request('/page', { [`${BASE}.bob.idToken`]: idToken() });

		await expect(rt.handle(req)).resolves.toBe(req);
	});
});

function jwksBody(kid: string) {
	return {
		keys: [
			{ kid, kty: 'RSA', alg: 'RS256', use: 'sig', n: poolJwk.n, e: poolJwk.e },
		],
	};
}

describe('cloudfront functions JWKS on a KVS miss', () => {
	test('fetches the JWKS with one call and forwards a valid token', async () => {
		const rt = runtime(JWKS_SETTINGS);
		rt.answer(() => ({ status: 200, body: jwksBody('rotated-kid') }));
		const req = request(
			'/page',
			userCookies({ id: idToken({}, { kid: 'rotated-kid' }) }),
		);

		await expect(rt.handle(req)).resolves.toBe(req);
		expect(rt.calls).toHaveLength(1);
		expect(rt.calls[0].path).toBe(JWKS_PATH);
		expect(rt.calls[0].options.originId).toBe('cognito-idp');
		expect(rt.calls[0].options.method).toBeUndefined();
	});

	test('uses the KVS copy without a call when the kid is there', async () => {
		const rt = runtime(JWKS_SETTINGS);
		const req = request('/page', userCookies({ id: idToken() }));

		await expect(rt.handle(req)).resolves.toBe(req);
		expect(rt.calls).toHaveLength(0);
	});

	test.each([
		[
			'a kid the JWKS does not have',
			idToken({}, { kid: 'forged-kid' }),
			jwksBody('other-kid'),
		],
		[
			'a forged signature on a fetched kid',
			idToken({}, { kid: 'rotated-kid', key: otherKey.privateKey }),
			jwksBody('rotated-kid'),
		],
		[
			'a JWKS key that is not RSA',
			idToken({}, { kid: 'ec-kid' }),
			{ keys: [{ kid: 'ec-kid', kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }] },
		],
	])('redirects to the hosted UI for %s', async (_name, token, body) => {
		const rt = runtime(JWKS_SETTINGS);
		rt.answer(() => ({ status: 200, body }));
		const result = await rt.handle(
			request('/page', userCookies({ id: token })),
		);

		expect(location(result).pathname).toBe('/oauth2/authorize');
		expect(rt.calls).toHaveLength(1);
	});

	test.each([
		['TypeError', null],
		['TimeoutError', null],
		['a 500', 500],
		['a body that is not JSON', 200],
	])(
		'fails closed with 503 when the JWKS cannot be fetched (%s)',
		async (name, status) => {
			const rt = runtime(JWKS_SETTINGS);
			if (status === null) rt.fail(name);
			else rt.answer(() => ({ status, body: '<html>' }));
			const result = asResponse(
				await rt.handle(
					request(
						'/page',
						userCookies({ id: idToken({}, { kid: 'rotated-kid' }) }),
					),
				),
			);

			expect(result.statusCode).toBe(503);
			expect(result.body).toBe('{"error":"jwks_unavailable"}');
		},
	);

	test('without jwksOriginId a KVS miss is refused with no call', async () => {
		const rt = runtime(SETTINGS);
		const result = await rt.handle(
			request(
				'/page',
				userCookies({ id: idToken({}, { kid: 'rotated-kid' }) }),
			),
		);

		expect(location(result).pathname).toBe('/oauth2/authorize');
		expect(rt.calls).toHaveLength(0);
	});

	test('an expired token with an unknown kid spends the call on the refresh, not the JWKS', async () => {
		const rt = runtime(JWKS_SETTINGS);
		rt.answer(() => ({
			status: 200,
			body: {
				id_token: idToken({}, { kid: 'new-kid' }),
				access_token: accessToken(),
			},
		}));
		const cookies = userCookies({
			id: idToken({ exp: now() - 10 }, { kid: 'unknown-kid' }),
			refresh: 'refresh-token',
		});
		const result = asResponse(await rt.handle(request('/page', cookies)));

		expect(result.statusCode).toBe(302);
		expect(rt.calls).toHaveLength(1);
		expect(rt.calls[0].path).toBe('/oauth2/token');
	});
});

describe('cloudfront functions refresh', () => {
	test('refreshes an expired token with one call and sets new cookies', async () => {
		const rt = runtime();
		const fresh = idToken();
		rt.answer(() => ({
			status: 200,
			body: { id_token: fresh, access_token: accessToken() },
		}));
		const cookies = userCookies({
			id: idToken({ exp: now() - 10 }),
			refresh: 'refresh-token',
		});
		const result = asResponse(
			await rt.handle(request('/page', cookies, { q: 'v' })),
		);

		expect(rt.calls).toHaveLength(1);
		expect(rt.calls[0].path).toBe('/oauth2/token');
		expect(rt.calls[0].options.originId).toBe('cognito');
		expect(Object.fromEntries(rt.calls[0].form)).toStrictEqual({
			grant_type: 'refresh_token',
			client_id: CLIENT_ID,
			refresh_token: 'refresh-token',
		});
		expect(result.headers.location.value).toBe(`https://${HOST}/page?q=v`);
		expect(result.cookies?.[`${BASE}.alice.idToken`]?.value).toBe(fresh);
		expect(result.cookies?.[`${BASE}.alice.refreshToken`]).toBeUndefined();
	});

	test('refreshes when only the refresh token cookie is left', async () => {
		const rt = runtime();
		rt.answer(() => ({
			status: 200,
			body: { id_token: idToken(), access_token: accessToken() },
		}));
		const result = await rt.handle(
			request('/page', userCookies({ refresh: 'refresh-token' })),
		);

		expect(location(result).pathname).toBe('/page');
		expect(rt.calls).toHaveLength(1);
	});

	test('starts over at the hosted UI when Cognito rejects the refresh token', async () => {
		const rt = runtime();
		rt.answer(() => ({ status: 400, body: { error: 'invalid_grant' } }));
		const cookies = userCookies({
			id: idToken({ exp: now() - 10 }),
			refresh: 'revoked',
		});
		const result = asResponse(await rt.handle(request('/page', cookies)));

		expect(location(result).pathname).toBe('/oauth2/authorize');
		expect(
			result.cookies?.[`${BASE}.alice.refreshToken`]?.attributes,
		).toContain('Expires=Thu, 01 Jan 1970');
	});

	test.each(['TypeError', 'TimeoutError', 'InternalError'])(
		'fails closed with 503 when Cognito cannot be reached (%s)',
		async (name) => {
			const rt = runtime();
			rt.fail(name);
			const cookies = userCookies({
				id: idToken({ exp: now() - 10 }),
				refresh: 'refresh-token',
			});
			const result = asResponse(await rt.handle(request('/page', cookies)));

			expect(result.statusCode).toBe(503);
			expect(result.headers['x-cognito-at-edge-error'].value).toContain(name);
		},
	);
});

describe('cloudfront functions callback', () => {
	const tokens = () => ({
		id_token: idToken(),
		access_token: accessToken(),
		refresh_token: 'new-refresh',
	});

	test('exchanges the code with PKCE and sets the cookies', async () => {
		const rt = runtime();
		rt.answer(() => ({ status: 200, body: tokens() }));
		const result = asResponse(
			await rt.handle(
				request('/parseauth', stateCookie('s1', 'verifier', '/a?b=c'), {
					code: 'the-code',
					state: 's1',
				}),
			),
		);

		expect(Object.fromEntries(rt.calls[0].form)).toStrictEqual({
			grant_type: 'authorization_code',
			client_id: CLIENT_ID,
			code: 'the-code',
			redirect_uri: `https://${HOST}/parseauth`,
			code_verifier: 'verifier',
		});
		expect(rt.calls[0].options.headers).toStrictEqual({
			'content-type': 'application/x-www-form-urlencoded',
		});
		expect(result.headers.location.value).toBe(`https://${HOST}/a?b=c`);
		expect(Object.keys(result.cookies || {}).sort()).toStrictEqual(
			[
				`${BASE}.LastAuthUser`,
				`${BASE}.alice.accessToken`,
				`${BASE}.alice.idToken`,
				`${BASE}.alice.refreshToken`,
				`${BASE}.alice.tokenScopesString`,
				STATE_COOKIE,
			].sort(),
		);
		expect(result.cookies?.[`${BASE}.alice.idToken`]?.attributes).toMatch(
			/^Secure; Path=\/; Expires=.+; HttpOnly; SameSite=Lax$/,
		);
		expect(result.cookies?.[STATE_COOKIE]?.attributes).toContain('1970');
	});

	test.each([
		[
			'a state that does not match',
			stateCookie('s1', 'v', '/'),
			{ code: 'c', state: 's2' },
		],
		['no state cookie', {}, { code: 'c', state: 's1' }],
	])('refuses %s with 400 and no call', async (_name, cookies, query) => {
		const rt = runtime();
		const result = asResponse(
			await rt.handle(request('/parseauth', cookies, query)),
		);

		expect(result.statusCode).toBe(400);
		expect(result.body).toBe('{"error":"invalid_state"}');
		expect(rt.calls).toHaveLength(0);
	});

	test('answers 400 when the hosted UI sends an error instead of a code', async () => {
		const rt = runtime();
		const result = asResponse(
			await rt.handle(request('/parseauth', {}, { error: 'access_denied' })),
		);

		expect(result.statusCode).toBe(400);
		expect(result.headers['x-cognito-at-edge-error'].value).toBe(
			'access_denied',
		);
	});

	test('answers 400 when Cognito rejects the code', async () => {
		const rt = runtime();
		rt.answer(() => ({ status: 400, body: { error: 'invalid_grant' } }));
		const result = asResponse(
			await rt.handle(
				request('/parseauth', stateCookie('s', 'v', '/'), {
					code: 'c',
					state: 's',
				}),
			),
		);

		expect(result.statusCode).toBe(400);
		expect(result.headers['x-cognito-at-edge-error'].value).toBe(
			'400 invalid_grant',
		);
	});

	test('fails closed with 503 when Cognito cannot be reached', async () => {
		const rt = runtime();
		rt.fail('TypeError');
		const result = asResponse(
			await rt.handle(
				request('/parseauth', stateCookie('s', 'v', '/'), {
					code: 'c',
					state: 's',
				}),
			),
		);

		expect(result.statusCode).toBe(503);
	});

	const exchange = (rt: ReturnType<typeof runtime>) =>
		rt.handle(
			request('/parseauth', stateCookie('s', 'v', '/'), {
				code: 'c',
				state: 's',
			}),
		);

	test.each([
		[
			'a signature that does not match the key in KVS',
			{ key: otherKey.privateKey },
			{},
		],
		['a wrong audience', {}, { aud: 'another-client' }],
	])(
		'answers 502 when the issued token has %s',
		async (_name, options, claims) => {
			const rt = runtime(JWKS_SETTINGS);
			rt.answer(() => ({
				status: 200,
				body: { ...tokens(), id_token: idToken(claims, options) },
			}));
			const result = asResponse(await exchange(rt));

			expect(result.statusCode).toBe(502);
			expect(rt.calls).toHaveLength(1);
		},
	);

	test('sets the cookies for an issued token whose kid is not in KVS, verified on the next request', async () => {
		const rt = runtime(JWKS_SETTINGS);
		const issued = idToken({}, { kid: 'new-kid' });
		rt.answer(() => ({ status: 200, body: { ...tokens(), id_token: issued } }));
		const result = asResponse(await exchange(rt));

		expect(result.statusCode).toBe(302);
		expect(result.cookies?.[`${BASE}.alice.idToken`]?.value).toBe(issued);
		expect(rt.calls).toHaveLength(1);
		expect(rt.calls[0].path).toBe('/oauth2/token');
	});

	test.each([
		'//evil.example.com/',
		'/\\evil.example.com',
		'https://evil.example.com',
	])('never redirects off site (%s)', async (back) => {
		const rt = runtime();
		rt.answer(() => ({ status: 200, body: tokens() }));
		const result = await rt.handle(
			request('/parseauth', stateCookie('s', 'v', back), {
				code: 'c',
				state: 's',
			}),
		);

		expect(asResponse(result).headers.location.value).toBe(`https://${HOST}/`);
	});
});

describe('cloudfront functions logout', () => {
	test('revokes the refresh token, clears the cookies and ends the hosted UI session', async () => {
		const rt = runtime();
		rt.answer(() => ({ status: 200, body: '' }));
		const result = asResponse(
			await rt.handle(
				request(
					'/logout',
					userCookies({ id: idToken(), refresh: 'refresh-token' }),
				),
			),
		);
		const url = location(result);

		expect(rt.calls[0].path).toBe('/oauth2/revoke');
		expect(Object.fromEntries(rt.calls[0].form)).toStrictEqual({
			token: 'refresh-token',
			client_id: CLIENT_ID,
		});
		expect(url.origin + url.pathname).toBe(`https://${DOMAIN}/logout`);
		expect(url.searchParams.get('logout_uri')).toBe(`https://${HOST}/`);
		expect(Object.keys(result.cookies || {})).toHaveLength(3);
		expect(result.cookies?.[`${BASE}.alice.idToken`]?.value).toBe('');
	});

	test('clears the cookies even when the revoke call fails', async () => {
		const rt = runtime({ ...SETTINGS, cognitoLogout: false });
		rt.fail('TimeoutError');
		const result = asResponse(
			await rt.handle(
				request('/logout', userCookies({ refresh: 'refresh-token' })),
			),
		);

		expect(result.headers.location.value).toBe(`https://${HOST}/`);
		expect(
			result.cookies?.[`${BASE}.alice.refreshToken`]?.attributes,
		).toContain('1970');
	});
});
