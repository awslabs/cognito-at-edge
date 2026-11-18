# Cognito@Edge with CloudFront Functions

This folder holds a CloudFront Functions version of the `Authenticator.handle()` flow. It is one viewer-request function (runtime `cloudfront-js-2.0`) that you generate from your settings and attach to the cache behaviors you want to protect. No Lambda@Edge function is involved.

The function:

- Reads the same cookies the Lambda@Edge `Authenticator` writes (`CognitoIdentityServiceProvider.<appId>.<username>.idToken`, `.accessToken`, `.refreshToken`, `.LastAuthUser`), so you can move a site from one to the other without signing users out.
- Verifies the ID token (or the access token, with `tokenUse: 'access'`) at the edge: RS256 signature, `iss`, `aud` (or `client_id`), `token_use` and `exp`. The user pool's public keys are cached in a CloudFront KeyValueStore, so a valid token whose key is cached is forwarded with no network call. On a KVS miss (a key that was never seeded, or a new key after rotation) the function fetches the JWKS from the user pool's issuer with one network call, then verifies.
- Redirects a viewer without a valid token to the Cognito hosted UI. The redirect carries a random `state` and a PKCE `code_challenge` (S256). The state, the PKCE verifier and the page the viewer asked for are kept in a short-lived `HttpOnly` cookie.
- On the callback path, checks `state`, then exchanges the authorization code with one network call (`cf.fetch`) to the Cognito token endpoint, checks the new token (see below), sets the cookies and redirects to the original page.
- Refreshes an expired token with one call to the token endpoint (`grant_type=refresh_token`), then redirects to the same URL with the new cookies.
- On the logout path, revokes the refresh token with one call, clears the cookies and redirects. With `cognitoLogout: true` it also ends the hosted UI session.

Each invocation makes at most one network call, as CloudFront Functions requires.

## One call per invocation, and none after WebCrypto

The runtime allows one network call per invocation, and no call once WebCrypto has run. So every path decides its call from the token's header (`kid`) and `exp`, read without any crypto, before the signature check:

| Request                                    | The call                                                    | Key check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Unexpired token, `kid` in KVS              | none                                                        | signature with the KVS key                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Unexpired token, `kid` not in KVS          | `GET /<userPoolId>/.well-known/jwks.json` on `jwksOriginId` | signature with the fetched key; a `kid` the JWKS does not have (a forged or retired key) goes to the hosted UI; a JWKS that cannot be fetched is a `503 jwks_unavailable`                                                                                                                                                                                                                                                                                                                        |
| Expired token + refresh token              | `POST /oauth2/token` (refresh)                              | the expired token's key is not needed, so an unknown `kid` costs nothing; see the next row for the new token                                                                                                                                                                                                                                                                                                                                                                                     |
| Callback with a code                       | `POST /oauth2/token` (code)                                 | see the next row                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Tokens just returned by the token endpoint | (the call is spent)                                         | These come straight from Cognito over the function's own TLS call, so they are authentic. The function still checks `iss`, `aud`/`client_id` and `token_use`, and the signature when the key is in KVS (`502` if it fails, which catches a misconfigured origin). If the `kid` is not in KVS, a second call would be needed, so the function sets the cookies without the signature check and redirects; the next request fetches the JWKS and verifies the cookie before any content is served. |
| Logout                                     | `POST /oauth2/revoke`                                       | none: the cookies are cleared whatever they hold                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

The two cases that would need two calls (refresh or code exchange, then a JWKS fetch for an unknown `kid`) are therefore split across the redirect that follows them. No content is served on a token whose signature has not been checked.

## How it calls Cognito

A CloudFront Function cannot call a URL. It calls an origin of the same distribution by its origin ID. Add your user pool domain (for example `my-prefix.auth.us-east-1.amazoncognito.com`) as a custom origin (HTTPS only) on the distribution that runs the function. That origin needs no cache behavior, so viewers never reach it. Network calls must be available for the distribution: they are not supported on distributions that use continuous deployment or the free pricing plan.

If Cognito cannot be reached (DNS or TLS failure, the fixed 1 second timeout, or an internal error), the callback, refresh and logout paths return `503` with an `x-cognito-at-edge-error` header (logout still clears the cookies). A viewer with a valid, unexpired token whose key is in KVS is not affected, because that path makes no call. The issuer origin (`jwksOriginId`) is called the same way; if the JWKS cannot be fetched on a KVS miss, the request is refused with `503 jwks_unavailable`.

## Usage

1. Generate the function code from your settings:

   ```shell
   cat > settings.json <<'EOF'
   {
   	"region": "us-east-1",
   	"userPoolId": "us-east-1_tyo1a1FHH",
   	"userPoolAppId": "63gcbm2jmskokurt5ku9fhejc6",
   	"userPoolDomain": "my-prefix.auth.us-east-1.amazoncognito.com",
   	"cognitoOriginId": "cognito",
   	"logoutPath": "/logout",
   	"cognitoLogout": true,
   	"httpOnly": true,
   	"sameSite": "Lax"
   }
   EOF
   node cloudfront-functions/build.js settings.json > function.js
   ```

   From the npm package, the same files ship under `node_modules/cognito-at-edge/cloudfront-functions/`:

   ```shell
   npm install cognito-at-edge
   node node_modules/cognito-at-edge/cloudfront-functions/build.js settings.json > function.js
   ```

   From Node.js (for example in a CDK app): `require('cognito-at-edge/cloudfront-functions/build.js').buildFunction(settings)` (or `./cloudfront-functions/build.js` from a clone). The build checks the settings, the 10 KB function size limit and syntax that the runtime does not support.

2. Create a KeyValueStore and associate it with the function. Add the user pool's issuer, `cognito-idp.<region>.amazonaws.com`, as a custom origin (HTTPS only, no cache behavior) and set its ID as `jwksOriginId`: on a KVS miss the function fetches `/<userPoolId>/.well-known/jwks.json` from it. Seeding the store is optional, a warm start that saves that call: write each public key to key `jwk.<kid>` with value `{"n":"...","e":"..."}` (a KVS value is limited to 1 KB, so the whole JWKS does not fit in one key). [`test-stack/lambda/seed-jwks.mjs`](test-stack/lambda/seed-jwks.mjs) does this as a custom resource. Without `jwksOriginId`, the function relies on the seeded keys only.
3. Create the CloudFront Function with runtime `cloudfront-js-2.0` and the generated code, associate the KeyValueStore with it, and attach it to your behaviors as a viewer-request function.
4. Add the user pool domain as an origin of the distribution, with the ID you set in `cognitoOriginId`, and the issuer origin from step 2.
5. In the app client, allow the authorization code grant, and add `https://<your domain><parseAuthPath>` as a callback URL. With `cognitoLogout: true`, also add the logout redirect as a sign-out URL. The app client must not have a client secret.

### Settings

| Setting                | Default      | Description                                                                                                                                                  |
| ---------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `region`               | (required)   | User pool region                                                                                                                                             |
| `userPoolId`           | (required)   | User pool ID                                                                                                                                                 |
| `userPoolAppId`        | (required)   | App client ID (a public client, no secret)                                                                                                                   |
| `userPoolDomain`       | (required)   | User pool domain, used in the hosted UI redirects                                                                                                            |
| `cognitoOriginId`      | (required)   | ID of the distribution origin that points at `userPoolDomain`                                                                                                |
| `jwksOriginId`         | (none)       | ID of the distribution origin that points at `cognito-idp.<region>.amazonaws.com`. Without it a key missing from KVS is not fetched and the token is refused |
| `tokenUse`             | `id`         | Token to verify: `id` (as the Lambda@Edge version) or `access`                                                                                               |
| `parseAuthPath`        | `/parseauth` | Callback path that receives `?code=&state=`                                                                                                                  |
| `logoutPath`           | (none)       | Path that signs the user out                                                                                                                                 |
| `logoutRedirectUri`    | `/`          | Where to go after logout: a path on the same host, or an absolute URL                                                                                        |
| `cognitoLogout`        | `false`      | Also end the hosted UI session: redirect through `https://<userPoolDomain>/logout` with `logoutRedirectUri` as `logout_uri`                                  |
| `cookieExpirationDays` | `365`        | Lifetime of the token cookies. Match it to the refresh token validity of the app client                                                                      |
| `cookiePath`           | `/`          | `Path` attribute of the cookies                                                                                                                              |
| `cookieDomain`         | (none)       | `Domain` attribute of the token cookies. Without it the cookies are host-only                                                                                |
| `httpOnly`             | `false`      | `HttpOnly` on the token cookies (the state cookie is always `HttpOnly`)                                                                                      |
| `sameSite`             | (none)       | `Strict`, `Lax` or `None`. `Strict` drops the cookies on the redirect back from the hosted UI; use `Lax`                                                     |

## What the CloudFront Functions version does not support

Compared with the Lambda@Edge `Authenticator`:

- **App client secrets** (`userPoolAppSecret`). The function would have to carry the secret in its code or in KVS, where anyone who can read the function or the store can see it. Use a public app client; PKCE protects the code exchange instead.
- **`csrfProtection` with a signed nonce.** The function always sends `state` and PKCE (S256) and keeps them in an `HttpOnly` cookie; there is no HMAC-signed nonce and no `nonceSigningSecret`.
- **The authentication gateway handlers** (`handleSignIn`, `handleParseAuth`, `handleRefreshToken`, `handleSignOut`). Only the `handle()` flow is implemented, with a callback path and an optional logout path.
- **A callback on the site root.** `parseAuthPath` is required (default `/parseauth`); the Lambda@Edge version can take `?code=` on any path.
- **Refresh after a failed verification.** The Lambda@Edge version tries the refresh token whenever the ID token does not verify. The function refreshes only when the token is expired or missing, and sends a token with a bad signature or wrong claims to the hosted UI. The runtime does not allow a network call after WebCrypto ran, so the decision to refresh is taken from the `exp` claim before the signature is checked. Cognito still validates the refresh token.
- **A JWKS cache that fills itself.** `aws-jwt-verify` downloads the JWKS and keeps it in memory. A CloudFront Function cannot write to KVS, so a fetched key is used for that request only: until you seed it, every request with that `kid` spends its one call on the JWKS (and adds that round trip to its latency). A token with an unknown `kid`, including a forged one, also costs one JWKS fetch per request. Re-seed after Cognito rotates its keys to get back to zero calls; until then, rotation still works through the fetch.
- **Signature verification of freshly issued tokens with an unknown `kid`** in the same invocation (see the table above): it is done on the next request instead.
- **Per-token cookie settings** (`cookieSettingsOverrides`) and **`disableCookieDomain`**. One set of attributes applies to all token cookies, and cookies are host-only unless you set `cookieDomain`.
- **Logging** (`logLevel`). Errors are reported in the `x-cognito-at-edge-error` response header.
- **Usernames outside the cookie-name character set.** The username is used as-is in cookie names; the Lambda@Edge version URI-encodes it. Pools that sign in with email or phone aliases use a UUID username and are not affected.
- **Algorithms other than RS256**, and clock-skew tolerance on `exp`.
- **Slow Cognito responses.** Each call has a fixed 1 second timeout, after which the request fails closed with `503`.

## Test stack

[`test-stack/`](test-stack/) is a CDK app that deploys everything needed to try the function: a user pool with a hosted UI domain and a test user (the password is generated in AWS Secrets Manager and set at deploy time), a private S3 bucket as the protected origin, a KeyValueStore seeded with the JWKS, and a distribution. A second behavior, `/unreachable/*`, runs a build of the function whose Cognito and JWKS origins do not resolve, to show the fail-closed paths.

```shell
cd cloudfront-functions/test-stack
npm install
npx playwright install chromium
npm run deploy           # us-east-1; tags from the optional "tags" context
npm run e2e              # add -- --wait-expiry to also wait for a real token to expire (about 5 minutes)
npm run destroy
```

The site objects are uploaded with `Cache-Control: private, no-store`: the function decides at request time, so a protected page the browser keeps in its own cache would still show after logout.

The end-to-end test signs in through the hosted UI with headless Chromium, then checks the protected page, forged, expired and wrong-audience tokens, refresh, the callback, Cognito being unreachable, and logout. It also deletes the signing key from KVS to show the JWKS fetch (and the 503 when the JWKS endpoint is unreachable), restores it, and sends a token with a forged `kid`; it needs `cloudfront-keyvaluestore` read and write permissions on the stack's KeyValueStore.
