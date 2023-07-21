# Cognito@Edge

*Cognito authentication made easy to protect your website with CloudFront and Lambda@Edge.*

This Node.js package helps you verify that users making requests to a CloudFront distribution are authenticated using a Cognito user pool. It achieves that by looking at the cookies included in the request and, if the requester is not authenticated, it will redirect then to the user pool's login page.

![Architecture](./doc/architecture.png)

### Alternatives

This package allows you to easily parse and verify Cognito cookies in a Lambda@Edge function. If you want full control over the configuration of AWS resources (CloudFront, Cognito, Lambda@Edge...), this is the solution for you.

If you want to try it out easily or to quickstart a new project, we recommend having a look at the [cognito-at-edge-federated-ui-sample](https://github.com/aws-samples/cognito-at-edge-federated-ui-sample) repository. It allows you to configure and deploy a sample application which uses Cognito@Edge in a few CLI commands.

If you need more configuration options (e.g. bring your own user pool or CloudFront distribution), you may want to use [this Serverless Application Repository application](https://console.aws.amazon.com/lambda/home?region=us-east-1#/create/app?applicationId=arn:aws:serverlessrepo:us-east-1:520945424137:applications/cloudfront-authorization-at-edge) ([GitHub](https://github.com/aws-samples/cloudfront-authorization-at-edge)) which provides a complete Auth@Edge solution. It does not use Cognito@Edge, but provides similar functionality.

## Getting started

### How To Install

The preferred way to install the AWS cognito-at-edge for Node.js is to use the [npm](http://npmjs.org/) package manager for Node.js. Simply type the following into a terminal window:

``` shell
npm install cognito-at-edge
```

### Usage

To use the package, you must create a [Lambda@Edge function](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-the-edge.html) and associate it with the CloudFront distribution's *viewer request* events.

Within your Lambda@Edge function, you can import and use the `Authenticator` class as shown here:

``` js
const { Authenticator } = require('cognito-at-edge');

const authenticator = new Authenticator({
  // Replace these parameter values with those of your own environment
  region: 'us-east-1', // user pool region
  userPoolId: 'us-east-1_tyo1a1FHH', // user pool ID
  userPoolAppId: '63gcbm2jmskokurt5ku9fhejc6', // user pool app client ID
  userPoolDomain: 'domain.auth.us-east-1.amazoncognito.com', // user pool domain
});

exports.handler = async (request) => authenticator.handle(request);
```

For an explanation of the interactions between CloudFront, Cognito and Lambda@Edge, we recommend reading this [AWS blog article](https://aws.amazon.com/blogs/networking-and-content-delivery/authorizationedge-how-to-use-lambdaedge-and-json-web-tokens-to-enhance-web-application-security/) which describe the required architecture to authenticate requests in CloudFront with Cognito.

## Reference - Authenticator Class

### Authenticator(params)

* `params` *Object* Authenticator parameters:
  * `region` *string* Cognito UserPool region (eg: `us-east-1`)
  * `userPoolId` *string* Cognito UserPool ID (eg: `us-east-1_tyo1a1FHH`)
  * `userPoolAppId` *string* Cognito UserPool Application ID (eg: `63gcbm2jmskokurt5ku9fhejc6`)
  * `userPoolAppSecret` *string* (Optional) Cognito UserPool Application Secret (eg: `oh470px2i0uvy4i2ha6sju0vxe4ata9ol3m63ufhs2t8yytwjn7p`)
  * `userPoolDomain` *string* Cognito UserPool domain (eg: `your-domain.auth.us-east-1.amazoncognito.com`)
  * `cookieExpirationDays` *number* (Optional) Number of day to set cookies expiration date, default to 365 days (eg: `365`). It's recommended to set this value to match `refreshTokenValidity` parameter of the pool client.
  * `disableCookieDomain` *boolean* (Optional) Sets domain attribute in cookies, defaults to false (eg: `false`)
  * `httpOnly` *boolean* (Optional) Forbids JavaScript from accessing the cookies, defaults to false (eg: `false`). Note, if this is set to `true`, the cookies will not be accessible to Amplify auth if you are using it client side.
  * `sameSite` *Strict | Lax | None* (Optional) Allows you to declare if your cookie should be restricted to a first-party or same-site context (eg: `SameSite=None`).
  * `cookiePath` *string* (Optional) Sets Path attribute in cookies
  * `cookieDomain` *string* (Optional) Sets the domain name used for the token cookies
  * `cookieSettingsOverrides` *object* (Optional) Cookie settings overrides for different token cookies -- idToken, accessToken and refreshToken
    * `idToken` *CookieSettings* (Optional) Setting overrides to use for idToken
      * `expirationDays` *number* (Optional) Number of day to set cookies expiration date, default to 365 days (eg: `365`). It's recommended to set this value to match `refreshTokenValidity` parameter of the pool client.
      * `path` *string* (Optional) Sets Path attribute in cookies
      * `httpOnly` *boolean* (Optional) Forbids JavaScript from accessing the cookies, defaults to false (eg: `false`). Note, if this is set to `true`, the cookies will not be accessible to Amplify auth if you are using it client side.
      * `sameSite` *Strict | Lax | None* (Optional) Allows you to declare if your cookie should be restricted to a first-party or same-site context (eg: `SameSite=None`).
    * `accessToken` *CookieSettings* (Optional) Setting overrides to use for accessToken
    * `refreshToken` *CookieSettings* (Optional) Setting overrides to use for refreshToken
  * `logoutConfiguration` *object* (Optional) Enables logout functionality
    * `logoutUri` *string* URI path, which when matched with request, logs user out by revoking tokens and clearing cookies
    * `logoutRedirectUri` *string* The URI to which the user is redirected to after logging them out
  * `parseAuthPath` *string* (Optional) URI path to use for the parse auth handler, when the library is used in an authentication gateway setup
  * `csrfProtection` *object* (Optional) Enables CSRF protection
    * `nonceSigningSecret` *string* Secret used for signing nonce cookies
  * `logLevel` *string* (Optional) Logging level. Default: `'silent'`. One of `'fatal'`, `'error'`, `'warn'`, `'info'`, `'debug'`, `'trace'` or `'silent'`.

*This is the class constructor.*

### handle(request)

* `request` *Object* Lambda@Edge request object
  * See AWS doc for details: [Lambda@Edge events](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html)

Use it as your Lambda Handler. It will authenticate each query.

```js
const authenticator = new Authenticator( ... );
exports.handler = async (request) => authenticator.handle(request);
```

### Authentication Gateway Setup
This library can also be used in an authentication gateway setup. If you have a frontend client application that uses AWS Cognito for authentication, it fetches and stores authentication tokens in the browser. Depending on where the tokens are stored in the browser (localStorage, cookies, sessionStorage), they may susceptible to token theft and XSS (Cross-Site Scripting). In order to mitigate this risk, a set of Lambda@Edge handlers can be deployed on a CloudFront distribution which act as an authentication gateway intermediary between the frontend app and Cognito. These handlers will authenticate and fetch tokens on the frontend's behalf and set them as [Secure; HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies) tokens inside the browser, thereby restricting access to other scripts in the app.

Handlers
1. `handleSignIn` (Can be mapped to `/signIn` in Cloudfront setup): Redirect users to Cognito's authorize endpoint after replacing redirect uri with its own -- for instance, `/parseAuth`.
1. `handleParseAuth` (Can be mapped to `/parseAuth`): Exchange Cognito's OAuth code for tokens. Store tokens in browser as HttpOnly cookies
1. `handleRefreshToken` (Can be mapped to `/refreshToken`): Refresh idToken and accessToken using refreshToken
1. `handleSignOut` (Can be mapped to `/signOut`): Revoke tokens, clear cookies and redirect user to the URL supplied

```js
// signIn Lambda Handler
const authenticator = new Authenticator( ... );
exports.handler = async (request) => authenticator.handleSignIn(request);

// Similar setup for parseAuth, refreshToken and signOut handlers
```


### Getting Help

The best way to interact with our team is through GitHub.  You can [open an issue](https://github.com/awslabs/cognito-at-edge/issues/new/choose) 
and choose from one of our templates for [bug reports](https://github.com/awslabs/cognito-at-edge/issues/new?assignees=&labels=bug%2C+needs-triage&template=---bug-report.md&title=), 
[feature requests](https://github.com/awslabs/cognito-at-edge/issues/new?assignees=&labels=feature-request&template=---feature-request.md&title=) or 
[question](https://github.com/awslabs/cognito-at-edge/issues/new?assignees=&labels=question%2C+needs-triage&template=---questions---help.md&title=).  

## Contributing

We welcome community contributions and pull requests. See [CONTRIBUTING.md](https://github.com/awslabs/cognito-at-edge/blob/main/CONTRIBUTING.md) for information on how to set up a development environment and submit code.

### License

This project is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html), see LICENSE.txt and NOTICE.txt for more information.
