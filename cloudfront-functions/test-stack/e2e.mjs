// End-to-end test of the deployed test stack: node e2e.mjs [--wait-expiry]
// Reads cdk-outputs.json (written by npm run deploy). The test user's password is read from
// Secrets Manager and only typed into the hosted UI; tokens are printed as 8 characters at most.
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
	SecretsManagerClient,
	GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { chromium } from 'playwright';

const outputs = Object.values(
	JSON.parse(readFileSync(new URL('cdk-outputs.json', import.meta.url))),
)[0];
const SITE = `https://${outputs.DistributionDomain}`;
const BASE = `CognitoIdentityServiceProvider.${outputs.ClientId}`;
const USER = outputs.TestUsername;
const WAIT_EXPIRY = process.argv.includes('--wait-expiry');

const results = [];
function check(name, ok, detail = '') {
	results.push({ name, ok });
	console.log(
		`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`,
	);
}
const short = (token) => `${String(token).slice(0, 8)}...`;

// One request, no redirects followed, like curl without -L.
async function get(path, cookies = {}) {
	const cookie = Object.entries(cookies)
		.map(([name, value]) => `${name}=${value}`)
		.join('; ');
	const response = await fetch(SITE + path, {
		redirect: 'manual',
		headers: cookie ? { cookie } : {},
	});
	const setCookies = {};
	response.headers.getSetCookie().forEach((line) => {
		const [pair] = line.split(';');
		const eq = pair.indexOf('=');
		setCookies[pair.slice(0, eq)] = pair.slice(eq + 1);
	});
	return {
		status: response.status,
		location: response.headers.get('location') || '',
		error: response.headers.get('x-cognito-at-edge-error') || '',
		body: await response.text(),
		setCookies,
	};
}

const b64url = (value) => Buffer.from(value).toString('base64url');
const claimsOf = (token) =>
	JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
const headerOf = (token) =>
	JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
const attackerKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
// A token with the pool's kid and any claims, signed with a key that is not the pool's.
function forge(realToken, claims) {
	const header = b64url(JSON.stringify(headerOf(realToken)));
	const payload = b64url(JSON.stringify({ ...claimsOf(realToken), ...claims }));
	const signature = sign(
		'sha256',
		Buffer.from(`${header}.${payload}`),
		attackerKey.privateKey,
	).toString('base64url');
	return `${header}.${payload}.${signature}`;
}
const isAuthorize = (r) =>
	r.status === 302 &&
	r.location.startsWith(`https://${outputs.CognitoDomain}/oauth2/authorize?`);
const sessionCookies = (tokens) => ({
	[`${BASE}.LastAuthUser`]: USER,
	...(tokens.id ? { [`${BASE}.${USER}.idToken`]: tokens.id } : {}),
	...(tokens.refresh
		? { [`${BASE}.${USER}.refreshToken`]: tokens.refresh }
		: {}),
});

async function login(browser) {
	const password = (
		await new SecretsManagerClient({ region: 'us-east-1' }).send(
			new GetSecretValueCommand({ SecretId: outputs.TestUserPasswordSecret }),
		)
	).SecretString;
	const context = await browser.newContext();
	const page = await context.newPage();
	await page.goto(`${SITE}/`);
	check(
		'browser lands on the hosted UI',
		page.url().startsWith(`https://${outputs.CognitoDomain}/`),
		new URL(page.url()).pathname,
	);
	await page.locator('input[name="username"]:visible').fill(USER);
	await page.locator('input[name="password"]:visible').fill(password);
	await page.locator('[name="signInSubmitButton"]:visible').click();
	await page.waitForURL(`${SITE}/`, { timeout: 15000 });
	const heading = await page.locator('#protected').textContent();
	check('after login the protected page renders', Boolean(heading), heading);
	const cookies = Object.fromEntries(
		(await context.cookies(SITE)).map((c) => [c.name, c]),
	);
	return { context, page, cookies };
}

async function main() {
	console.log(`site ${SITE}`);

	// --- Unauthenticated -----------------------------------------------------------
	const anonymous = await get('/?from=e2e');
	const authorize = new URL(anonymous.location || 'https://invalid');
	check(
		'no cookie: 302 to the hosted UI with PKCE S256',
		isAuthorize(anonymous) &&
			authorize.searchParams.get('code_challenge_method') === 'S256' &&
			authorize.searchParams.get('redirect_uri') === `${SITE}/parseauth`,
		`${anonymous.status}`,
	);
	check(
		'no cookie: state cookie set',
		Boolean(anonymous.setCookies[`${BASE}.state`]),
	);

	// --- Browser login ---------------------------------------------------------------
	const browser = await chromium.launch({ headless: true });
	try {
		const { context, page, cookies } = await login(browser);
		const id = cookies[`${BASE}.${USER}.idToken`];
		const refresh = cookies[`${BASE}.${USER}.refreshToken`];
		check(
			'login set HttpOnly Secure token cookies',
			Boolean(id && refresh && id.httpOnly && id.secure && refresh.httpOnly),
			`idToken ${short(id && id.value)}`,
		);
		check('state cookie cleared after login', !cookies[`${BASE}.state`]);
		const idToken = id.value;
		const refreshToken = refresh.value;

		// --- Cookie checks (curl-style) ----------------------------------------------
		const ok = await get('/', sessionCookies({ id: idToken }));
		check(
			'valid id token: 200 protected page',
			ok.status === 200 && ok.body.includes('protected'),
			`${ok.status}`,
		);

		const tampered = forge(idToken, { 'cognito:username': 'admin' });
		check(
			'forged signature: 302 to the hosted UI',
			isAuthorize(await get('/', sessionCookies({ id: tampered }))),
		);
		const wrongAud = forge(idToken, { aud: 'another-client' });
		check(
			'wrong audience: 302 to the hosted UI',
			isAuthorize(await get('/', sessionCookies({ id: wrongAud }))),
		);
		const none = `${b64url('{"alg":"none"}')}.${idToken.split('.')[1]}.`;
		check(
			'alg none: 302 to the hosted UI',
			isAuthorize(await get('/', sessionCookies({ id: none }))),
		);
		const expired = forge(idToken, { exp: Math.floor(Date.now() / 1000) - 60 });
		check(
			'expired token, no refresh token: 302 to the hosted UI',
			isAuthorize(await get('/', sessionCookies({ id: expired }))),
		);

		// --- Refresh: one cf.fetch to the Cognito token endpoint ----------------------
		const refreshed = await get(
			'/?r=1',
			sessionCookies({ id: expired, refresh: refreshToken }),
		);
		const newId = refreshed.setCookies[`${BASE}.${USER}.idToken`];
		check(
			'expired token + refresh token: 302 back with new cookies',
			refreshed.status === 302 &&
				refreshed.location === `${SITE}/?r=1` &&
				Boolean(newId),
			`${refreshed.status} ${refreshed.error} new idToken ${short(newId)}`,
		);
		const afterRefresh = await get('/', sessionCookies({ id: newId }));
		check(
			'refreshed id token: 200',
			afterRefresh.status === 200,
			`${afterRefresh.status}`,
		);

		// --- Callback --------------------------------------------------------------------
		const state = anonymous.setCookies[`${BASE}.state`];
		const stateValue = state.split('.')[0];
		const mismatch = await get(`/parseauth?code=x&state=other`, {
			[`${BASE}.state`]: state,
		});
		check(
			'callback, state mismatch: 400 invalid_state',
			mismatch.status === 400 && mismatch.body.includes('invalid_state'),
			`${mismatch.status}`,
		);
		const badCode = await get(
			`/parseauth?code=not-a-code-cognito-issued&state=${stateValue}`,
			{ [`${BASE}.state`]: state },
		);
		check(
			'callback, code Cognito rejects: 400 token_exchange_failed (live call)',
			badCode.status === 400 && badCode.body.includes('token_exchange_failed'),
			`${badCode.status} ${badCode.error}`,
		);

		// --- Cognito unreachable (/unreachable/* calls an origin that does not resolve) ---
		const unreachOk = await get(
			'/unreachable/index.html',
			sessionCookies({ id: newId }),
		);
		check(
			'Cognito unreachable, valid token: 200 (no call needed)',
			unreachOk.status === 200,
			`${unreachOk.status}`,
		);
		const unreachCb = await get(
			`/unreachable/parseauth?code=x&state=${stateValue}`,
			{ [`${BASE}.state`]: state },
		);
		check(
			'Cognito unreachable, callback: 503 auth_unavailable',
			unreachCb.status === 503 && unreachCb.body.includes('auth_unavailable'),
			`${unreachCb.status} ${unreachCb.error}`,
		);
		const unreachRefresh = await get(
			'/unreachable/index.html',
			sessionCookies({ id: expired, refresh: refreshToken }),
		);
		check(
			'Cognito unreachable, refresh: 503 auth_unavailable',
			unreachRefresh.status === 503,
			`${unreachRefresh.status} ${unreachRefresh.error}`,
		);

		// --- Optional: a real Cognito token past its exp (5 minute validity) ---------------
		if (WAIT_EXPIRY) {
			const waitMs = (claimsOf(newId).exp + 15) * 1000 - Date.now();
			console.log(
				`waiting ${Math.ceil(waitMs / 1000)} s for the id token to expire`,
			);
			await new Promise((resolve) => setTimeout(resolve, Math.max(0, waitMs)));
			check(
				'real expired token, no refresh: 302 to the hosted UI',
				isAuthorize(await get('/', sessionCookies({ id: newId }))),
			);
			const real = await get(
				'/',
				sessionCookies({ id: newId, refresh: refreshToken }),
			);
			check(
				'real expired token + refresh: 302 with new cookies',
				real.status === 302 &&
					Boolean(real.setCookies[`${BASE}.${USER}.idToken`]),
				`${real.status}`,
			);
		}

		// --- Logout: revoke, clear cookies, end the hosted UI session ------------------------
		await page.goto(`${SITE}/logout`);
		await page.waitForURL((url) => url.hostname === outputs.CognitoDomain, {
			timeout: 15000,
		});
		const left = (await context.cookies(SITE)).filter(
			(c) =>
				// The state cookie of the next sign-in is expected.
				c.name.startsWith(BASE) && c.name !== `${BASE}.state`,
		);
		check(
			'logout cleared the token cookies',
			left.length === 0,
			`${left.length} left`,
		);
		const loginForm = await page
			.locator('input[name="password"]:visible')
			.count();
		check(
			'after logout the hosted UI asks for the password again',
			loginForm > 0,
			new URL(page.url()).pathname,
		);
		const revoked = await get(
			'/',
			sessionCookies({ id: expired, refresh: refreshToken }),
		);
		check(
			'revoked refresh token: 302 to the hosted UI, cookies cleared',
			isAuthorize(revoked) &&
				revoked.setCookies[`${BASE}.${USER}.refreshToken`] === '',
			`${revoked.status}`,
		);
		await context.close();
	} finally {
		await browser.close();
	}

	const failed = results.filter((r) => !r.ok);
	console.log(
		`\n${results.length - failed.length}/${results.length} checks passed`,
	);
	process.exit(failed.length ? 1 : 0);
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
