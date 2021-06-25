## cognito-at-edge
*Serverless authentication solution to protect your website or Amplify application.*

![Architecture](./doc/architecture.png)

This NodeJS library authenticates CloudFront requests with Lambda@Edge based on a Cognito UserPool.

### Requirements
* NodeJS v10+ (install with [NVM](https://github.com/nvm-sh/nvm))
* aws-cli installed and configured ([installation guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html))

### Usage

Install the `cognito-at-edge` package:
```
npm install --save cognito-at-edge
```

Create a Lambda@Edge function with the following content and modify the parameters based on your configuration:
```
const { Authenticator } = require('cognito-at-edge');

const authenticator = new Authenticator({
  region: 'us-east-1', // user pool region
  userPoolId: 'us-east-1_tyo1a1FHH',
  userPoolAppId: '63gcbm2jmskokurt5ku9fhejc6',
  userPoolDomain: 'domain.auth.us-east-1.amazoncognito.com',
  logLevel: 'error',
});

exports.handler = async (request) => authenticator.handle(request);
```

**Every `request` will be authenticated by the `Authenticator.handle` function.**

### Getting started

Based on your requirements you can use one of the solutions below. They all provide the complete infrastructure leveraging `cognito-at-edge` to protect a website or an Amplify application.

*WIP*


### Reference
#### Authenticator Class
##### Authenticator(params)
* `params` *Object* Authenticator parameters:
  * `region` *string* Cognito UserPool region (eg: `us-east-1`)
  * `userPoolId` *string* Cognito UserPool ID (eg: `us-east-1_tyo1a1FHH`)
  * `userPoolAppId` *string* Cognito UserPool Application ID (eg: `63gcbm2jmskokurt5ku9fhejc6`)
  * `userPoolDomain` *string* Cognito UserPool domain (eg: `your-domain.auth.us-east-1.amazoncognito.com`)
  * `cookieExpirationDays` *number* (Optional) Number of day to set cookies expiration date, default to 365 days (eg: `365`)
  * `logLevel` *string* (Optional) Logging level. Default: `'silent'`. One of `'fatal'`, `'error'`, `'warn'`, `'info'`, `'debug'`, `'trace'` or `'silent'`.

*This is the class constructor.*

##### handle(request)
* `request` *Object* Lambda@Edge request Object
  * cf AWS doc for details: [Lambda@Edge events](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html)

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

## License
This project is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html), see 
LICENSE.txt and NOTICE.txt for more information.
