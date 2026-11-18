# Cognito@Edge with CloudFront Functions

This folder holds a CloudFront Functions version of the `Authenticator.handle()` flow. It is one viewer-request function (runtime `cloudfront-js-2.0`) that you generate from your settings and attach to the cache behaviors you want to protect. No Lambda@Edge function is involved.

The function:

- Reads the same cookies the Lambda@Edge `Authenticator` writes (`CognitoIdentityServiceProvider.<appId>.<username>.idToken`, `.accessToken`, `.refreshToken`, `.LastAuthUser`), so you can move a site from one to the other without signing users out.
- Verifies the ID token (or the access token, with `tokenUse: 'access'`) at the edge: RS256 signature, `iss`, `aud` (or `client_id`), `token_use` and `exp`. The user pool's public keys come from a CloudFront KeyValueStore, so a valid token is forwarded with no network call.
- Redirects a viewer without a valid token to the Cognito hosted UI. The redirect carries a random `state` and a PKCE `code_challenge` (S256). The state, the PKCE verifier and the page the viewer asked for are kept in a short-lived `HttpOnly` cookie.
- On the callback path, checks `state`, then exchanges the authorization code with one network call (`cf.fetch`) to the Cognito token endpoint, verifies the new token, sets the cookies and redirects to the original page.
- Refreshes an expired token with one call to the token endpoint (`grant_type=refresh_token`), then redirects to the same URL with the new cookies.
- On the logout path, revokes the refresh token with one call, clears the cookies and redirects. With `cognitoLogout: true` it also ends the hosted UI session.

Each invocation makes at most one network call, as CloudFront Functions requires.

## How it calls Cognito

A CloudFront Function cannot call a URL. It calls an origin of the same distribution by its origin ID. Add your user pool domain (for example `my-prefix.auth.us-east-1.amazoncognito.com`) as a custom origin (HTTPS only) on the distribution that runs the function. That origin needs no cache behavior, so viewers never reach it. Network calls must be available for the distribution: they are not supported on distributions that use continuous deployment or the free pricing plan.

If Cognito cannot be reached (DNS or TLS failure, the fixed 1 second timeout, or an internal error), the callback, refresh and logout paths return `503` with an `x-cognito-at-edge-error` header (logout still clears the cookies). A viewer with a valid, unexpired token is not affected, because that path makes no call.

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

   From Node.js (for example in a CDK app): `require('./cloudfront-functions/build.js').buildFunction(settings)`. The build checks the settings, the 10 KB function size limit and syntax that the runtime does not support.

2. Create a KeyValueStore and write each public key of the user pool to it, one key per key ID: key `jwk.<kid>`, value `{"n":"...","e":"..."}` from `https://cognito-idp.<region>.amazonaws.com/<userPoolId>/.well-known/jwks.json`. A KVS value is limited to 1 KB, so the whole JWKS does not fit in one key. [`test-stack/lambda/seed-jwks.mjs`](test-stack/lambda/seed-jwks.mjs) does this as a custom resource. Write the keys again if Cognito rotates them.
3. Create the CloudFront Function with runtime `cloudfront-js-2.0` and the generated code, associate the KeyValueStore with it, and attach it to your behaviors as a viewer-request function.
4. Add the user pool domain as an origin of the distribution, with the ID you set in `cognitoOriginId`.
5. In the app client, allow the authorization code grant, and add `https://<your domain><parseAuthPath>` as a callback URL. With `cognitoLogout: true`, also add the logout redirect as a sign-out URL. The app client must not have a client secret.

### Settings

| Setting                | Default      | Description                                                                                                                 |
| ---------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------- |
| `region`               | (required)   | User pool region                                                                                                            |
| `userPoolId`           | (required)   | User pool ID                                                                                                                |
| `userPoolAppId`        | (required)   | App client ID (a public client, no secret)                                                                                  |
| `userPoolDomain`       | (required)   | User pool domain, used in the hosted UI redirects                                                                           |
| `cognitoOriginId`      | (required)   | ID of the distribution origin that points at `userPoolDomain`                                                               |
| `tokenUse`             | `id`         | Token to verify: `id` (as the Lambda@Edge version) or `access`                                                              |
| `parseAuthPath`        | `/parseauth` | Callback path that receives `?code=&state=`                                                                                 |
| `logoutPath`           | (none)       | Path that signs the user out                                                                                                |
| `logoutRedirectUri`    | `/`          | Where to go after logout: a path on the same host, or an absolute URL                                                       |
| `cognitoLogout`        | `false`      | Also end the hosted UI session: redirect through `https://<userPoolDomain>/logout` with `logoutRedirectUri` as `logout_uri` |
| `cookieExpirationDays` | `365`        | Lifetime of the token cookies. Match it to the refresh token validity of the app client                                     |
| `cookiePath`           | `/`          | `Path` attribute of the cookies                                                                                             |
| `cookieDomain`         | (none)       | `Domain` attribute of the token cookies. Without it the cookies are host-only                                               |
| `httpOnly`             | `false`      | `HttpOnly` on the token cookies (the state cookie is always `HttpOnly`)                                                     |
| `sameSite`             | (none)       | `Strict`, `Lax` or `None`. `Strict` drops the cookies on the redirect back from the hosted UI; use `Lax`                    |

## What the CloudFront Functions version does not support

Compared with the Lambda@Edge `Authenticator`:

- **App client secrets** (`userPoolAppSecret`). The function would have to carry the secret in its code or in KVS, where anyone who can read the function or the store can see it. Use a public app client; PKCE protects the code exchange instead.
- **`csrfProtection` with a signed nonce.** The function always sends `state` and PKCE (S256) and keeps them in an `HttpOnly` cookie; there is no HMAC-signed nonce and no `nonceSigningSecret`.
- **The authentication gateway handlers** (`handleSignIn`, `handleParseAuth`, `handleRefreshToken`, `handleSignOut`). Only the `handle()` flow is implemented, with a callback path and an optional logout path.
- **A callback on the site root.** `parseAuthPath` is required (default `/parseauth`); the Lambda@Edge version can take `?code=` on any path.
- **Refresh after a failed verification.** The Lambda@Edge version tries the refresh token whenever the ID token does not verify. The function refreshes only when the token is expired or missing, and sends a token with a bad signature or wrong claims to the hosted UI. The runtime does not allow a network call after WebCrypto ran, so the decision to refresh is taken from the `exp` claim before the signature is checked. Cognito still validates the refresh token.
- **Fetching the JWKS at run time.** `aws-jwt-verify` downloads and caches the keys itself. The function reads them from KVS, which you seed and update on key rotation. A token signed with a key that is not in KVS is treated as invalid; at the callback it returns `502`.
- **Per-token cookie settings** (`cookieSettingsOverrides`) and **`disableCookieDomain`**. One set of attributes applies to all token cookies, and cookies are host-only unless you set `cookieDomain`.
- **Logging** (`logLevel`). Errors are reported in the `x-cognito-at-edge-error` response header.
- **Usernames outside the cookie-name character set.** The username is used as-is in cookie names; the Lambda@Edge version URI-encodes it. Pools that sign in with email or phone aliases use a UUID username and are not affected.
- **Algorithms other than RS256**, and clock-skew tolerance on `exp`.
- **Slow Cognito responses.** Each call has a fixed 1 second timeout, after which the request fails closed with `503`.

## Test stack

[`test-stack/`](test-stack/) is a CDK app that deploys everything needed to try the function: a user pool with a hosted UI domain and a test user (the password is generated in AWS Secrets Manager and set at deploy time), a private S3 bucket as the protected origin, a KeyValueStore seeded with the JWKS, and a distribution. A second behavior, `/unreachable/*`, runs a build of the function whose Cognito origin does not resolve, to show the fail-closed paths.

```shell
cd cloudfront-functions/test-stack
npm install
npx playwright install chromium
npm run deploy           # us-east-1; tags from the optional "tags" context
npm run e2e              # add -- --wait-expiry to also wait for a real token to expire (about 5 minutes)
npm run destroy
```

The site objects are uploaded with `Cache-Control: private, no-store`: the function decides at request time, so a protected page the browser keeps in its own cache would still show after logout.

The end-to-end test signs in through the hosted UI with headless Chromium, then checks the protected page, forged, expired and wrong-audience tokens, refresh, the callback, Cognito being unreachable, and logout.
