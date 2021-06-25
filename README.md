# Cognito@Edge

*Cognito authentication made easy to protect your website with CloudFront and Lambda@Edge.*

![Architecture](./doc/architecture.png)

This Node.js library authenticate CloudFront requests with Lambda@Edge based and a Cognito UserPool.

## Getting started
### How To Install
The preferred way to install the AWS cognito-at-edge for Node.js is to use the [npm](http://npmjs.org/) package manager for Node.js. Simply type the following into a terminal window:

``` shell
npm install cognito-at-edge
```

### Usage

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

For an explanation of the interactions between CloudFront, Cognito and Lambda@Edge, we recommend reading this [AWS blog article](https://aws.amazon.com/blogs/networking-and-content-delivery/authorizationedge-using-cookies-protect-your-amazon-cloudfront-content-from-being-downloaded-by-unauthenticated-users/) which describe the required architecture to authenticate requests in CloudFront with Cognito.

## Reference - Authenticator Class

### Authenticator(params)

* `params` *Object* Authenticator parameters:
  * `region` *string* Cognito UserPool region (eg: `us-east-1`)
  * `userPoolId` *string* Cognito UserPool ID (eg: `us-east-1_tyo1a1FHH`)
  * `userPoolAppId` *string* Cognito UserPool Application ID (eg: `63gcbm2jmskokurt5ku9fhejc6`)
  * `userPoolDomain` *string* Cognito UserPool domain (eg: `your-domain.auth.us-east-1.amazoncognito.com`)
  * `cookieExpirationDays` *number* (Optional) Number of day to set cookies expiration date, default to 365 days (eg: `365`)
  * `logLevel` *string* (Optional) Logging level. Default: `'silent'`. One of `'fatal'`, `'error'`, `'warn'`, `'info'`, `'debug'`, `'trace'` or `'silent'`.

*This is the class constructor.*

### handle(request)
* `request` *Object* Lambda@Edge request object
  * See AWS doc for details: [Lambda@Edge events](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html)

Use it as your Lambda Handler. It will authenticate each query.
```
const authenticator = new Authenticator( ... );
exports.handler = async (request) => authenticator.handle(request);
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
