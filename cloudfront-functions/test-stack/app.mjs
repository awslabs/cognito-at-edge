// Test stack for the CloudFront Functions option of cognito-at-edge.
//   - a Cognito user pool with a hosted UI prefix domain, a public app client and one test user
//     (its password is generated in Secrets Manager and set at deploy time, never output)
//   - a private S3 bucket (OAC) as the protected origin
//   - a KeyValueStore seeded with the pool's JWKS
//   - one distribution: default behavior protected by the function, the Cognito domain as an
//     extra origin with no behavior (the function's cf.fetch target), and /unreachable/* protected
//     by a second build of the function whose Cognito origin does not resolve
// Deploy: npx cdk deploy (us-east-1). Tags come from the optional "tags" context.
import { createRequire } from 'node:module';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as cdk from 'aws-cdk-lib';
import {
	aws_cloudfront as cloudfront,
	aws_cloudfront_origins as origins,
	aws_cognito as cognito,
	aws_iam as iam,
	aws_lambda as lambda,
	aws_lambda_nodejs as nodejs,
	aws_s3 as s3,
	aws_s3_deployment as s3deploy,
	aws_secretsmanager as secretsmanager,
	custom_resources as cr,
} from 'aws-cdk-lib';

const require = createRequire(import.meta.url);
const { buildFunction } = require('../build.js');
const here = path.dirname(fileURLToPath(import.meta.url));

const COGNITO_ORIGIN_ID = 'cognito';
const UNREACHABLE_ORIGIN_ID = 'cognito-unreachable';
const TEST_USERNAME = 'test-user';

class CognitoAtEdgeCffTestStack extends cdk.Stack {
	constructor(scope, id, props) {
		super(scope, id, props);

		// --- Cognito ------------------------------------------------------------------
		const userPool = new cognito.UserPool(this, 'UserPool', {
			selfSignUpEnabled: false,
			signInAliases: { username: true },
			accountRecovery: cognito.AccountRecovery.NONE,
			removalPolicy: cdk.RemovalPolicy.DESTROY,
		});
		// A prefix may not contain "cognito"; the stack id's first block keeps it unique.
		const stackGuid = cdk.Fn.select(2, cdk.Fn.split('/', this.stackId));
		const domainPrefix = cdk.Fn.join('-', [
			'cae-cff',
			cdk.Fn.select(0, cdk.Fn.split('-', stackGuid)),
		]);
		const domain = userPool.addDomain('HostedUi', {
			cognitoDomain: { domainPrefix },
		});
		const cognitoDomainName = `${domain.domainName}.auth.${this.region}.amazoncognito.com`;

		// Callback and logout URLs name the distribution, which is created later: they are set
		// by ClientUrls below. The values here are placeholders.
		const oauthScopes = ['openid', 'email', 'profile'];
		const client = userPool.addClient('Client', {
			generateSecret: false,
			authFlows: { userSrp: true },
			oAuth: {
				flows: { authorizationCodeGrant: true },
				scopes: oauthScopes.map((s) => cognito.OAuthScope.custom(s)),
				callbackUrls: ['https://localhost/parseauth'],
				logoutUrls: ['https://localhost/'],
			},
			idTokenValidity: cdk.Duration.minutes(5),
			accessTokenValidity: cdk.Duration.minutes(5),
			refreshTokenValidity: cdk.Duration.days(1),
			enableTokenRevocation: true,
			preventUserExistenceErrors: true,
		});

		const password = new secretsmanager.Secret(this, 'TestUserPassword', {
			description:
				'Password of the cognito-at-edge CloudFront Functions test user',
			generateSecretString: {
				passwordLength: 24,
				requireEachIncludedType: true,
				excludeCharacters: '"\'\\`{}/@ ',
			},
		});
		const createUser = new cr.AwsCustomResource(this, 'TestUser', {
			onCreate: {
				service: 'CognitoIdentityServiceProvider',
				action: 'adminCreateUser',
				parameters: {
					UserPoolId: userPool.userPoolId,
					Username: TEST_USERNAME,
					MessageAction: 'SUPPRESS',
				},
				physicalResourceId: cr.PhysicalResourceId.of(TEST_USERNAME),
			},
			policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
				resources: [userPool.userPoolArn],
			}),
			installLatestAwsSdk: false,
		});
		const setPasswordFn = new nodejs.NodejsFunction(this, 'SetPasswordFn', {
			entry: path.join(here, 'lambda', 'set-password.mjs'),
			runtime: lambda.Runtime.NODEJS_22_X,
			timeout: cdk.Duration.seconds(30),
		});
		password.grantRead(setPasswordFn);
		setPasswordFn.addToRolePolicy(
			new iam.PolicyStatement({
				actions: ['cognito-idp:AdminSetUserPassword'],
				resources: [userPool.userPoolArn],
			}),
		);
		const setPassword = new cdk.CustomResource(this, 'SetTestUserPassword', {
			serviceToken: new cr.Provider(this, 'SetPasswordProvider', {
				onEventHandler: setPasswordFn,
			}).serviceToken,
			properties: {
				UserPoolId: userPool.userPoolId,
				Username: TEST_USERNAME,
				SecretArn: password.secretArn,
			},
		});
		setPassword.node.addDependency(createUser);

		// --- KeyValueStore with the pool's public keys --------------------------------------
		const keyValueStore = new cloudfront.KeyValueStore(this, 'Jwks', {
			comment: 'cognito-at-edge: user pool JWKS, one key per kid',
		});
		const seedFn = new nodejs.NodejsFunction(this, 'SeedJwksFn', {
			entry: path.join(here, 'lambda', 'seed-jwks.mjs'),
			runtime: lambda.Runtime.NODEJS_22_X,
			timeout: cdk.Duration.seconds(30),
			// The KVS client and the SigV4a signer are not in the Lambda-provided SDK.
			bundling: { externalModules: [] },
		});
		seedFn.addToRolePolicy(
			new iam.PolicyStatement({
				actions: [
					'cloudfront-keyvaluestore:DescribeKeyValueStore',
					'cloudfront-keyvaluestore:UpdateKeys',
				],
				resources: [keyValueStore.keyValueStoreArn],
			}),
		);
		new cdk.CustomResource(this, 'SeedJwks', {
			serviceToken: new cr.Provider(this, 'SeedJwksProvider', {
				onEventHandler: seedFn,
			}).serviceToken,
			properties: {
				KvsARN: keyValueStore.keyValueStoreArn,
				JwksUrl: `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}/.well-known/jwks.json`,
			},
		});

		// --- CloudFront Functions -----------------------------------------------------------
		const settings = {
			region: this.region,
			userPoolId: userPool.userPoolId,
			userPoolAppId: client.userPoolClientId,
			userPoolDomain: cognitoDomainName,
			cognitoOriginId: COGNITO_ORIGIN_ID,
			parseAuthPath: '/parseauth',
			logoutPath: '/logout',
			logoutRedirectUri: '/',
			cognitoLogout: true,
			httpOnly: true,
			sameSite: 'Lax',
			cookieExpirationDays: 1,
		};
		const authFunction = new cloudfront.Function(this, 'AuthFunction', {
			comment: 'cognito-at-edge: Cognito auth, viewer request',
			runtime: cloudfront.FunctionRuntime.JS_2_0,
			code: cloudfront.FunctionCode.fromInline(buildFunction(settings)),
			keyValueStore,
		});
		const unreachableFunction = new cloudfront.Function(
			this,
			'UnreachableFunction',
			{
				comment:
					'cognito-at-edge: Cognito auth with an unreachable Cognito origin',
				runtime: cloudfront.FunctionRuntime.JS_2_0,
				code: cloudfront.FunctionCode.fromInline(
					buildFunction({
						...settings,
						cognitoOriginId: UNREACHABLE_ORIGIN_ID,
						parseAuthPath: '/unreachable/parseauth',
						logoutPath: '/unreachable/logout',
					}),
				),
				keyValueStore,
			},
		);
		// CloudFront rate-limits parallel function updates.
		unreachableFunction.node.addDependency(authFunction);

		// --- Protected origin and distribution ----------------------------------------------
		const bucket = new s3.Bucket(this, 'Site', {
			blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
			encryption: s3.BucketEncryption.S3_MANAGED,
			enforceSSL: true,
			removalPolicy: cdk.RemovalPolicy.DESTROY,
			autoDeleteObjects: true,
		});
		const siteOrigin = origins.S3BucketOrigin.withOriginAccessControl(bucket, {
			originId: 'site',
		});
		const behavior = (fn) => ({
			origin: siteOrigin,
			viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
			cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
			functionAssociations: [
				{
					function: fn,
					eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
				},
			],
		});
		const distribution = new cloudfront.Distribution(this, 'Distribution', {
			comment: 'cognito-at-edge CloudFront Functions test',
			defaultRootObject: 'index.html',
			priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
			defaultBehavior: behavior(authFunction),
			additionalBehaviors: { '/unreachable/*': behavior(unreachableFunction) },
		});
		// Origins the function calls with cf.fetch. Viewers never reach them: no behavior.
		// Origins[0] is the S3 site origin shared by both behaviors.
		const callOrigin = (id, domainName) => ({
			Id: id,
			DomainName: domainName,
			CustomOriginConfig: {
				OriginProtocolPolicy: 'https-only',
				OriginSSLProtocols: ['TLSv1.2'],
			},
		});
		const cfn = distribution.node.defaultChild;
		cfn.addPropertyOverride(
			'DistributionConfig.Origins.1',
			callOrigin(COGNITO_ORIGIN_ID, cognitoDomainName),
		);
		cfn.addPropertyOverride(
			'DistributionConfig.Origins.2',
			callOrigin(UNREACHABLE_ORIGIN_ID, 'cognito-unreachable.invalid'),
		);
		distribution.node.addDependency(domain);

		new s3deploy.BucketDeployment(this, 'SiteContent', {
			destinationBucket: bucket,
			sources: [s3deploy.Source.asset(path.join(here, 'site'))],
			// Protected pages must not be served from the browser cache after logout.
			cacheControl: [s3deploy.CacheControl.fromString('private, no-store')],
		});

		// --- Callback and logout URLs, now that the distribution exists ---------------------
		const site = `https://${distribution.distributionDomainName}`;
		const clientConfig = {
			UserPoolId: userPool.userPoolId,
			ClientId: client.userPoolClientId,
			CallbackURLs: [`${site}/parseauth`, `${site}/unreachable/parseauth`],
			LogoutURLs: [`${site}/`],
			AllowedOAuthFlows: ['code'],
			AllowedOAuthFlowsUserPoolClient: true,
			AllowedOAuthScopes: oauthScopes,
			SupportedIdentityProviders: ['COGNITO'],
			ExplicitAuthFlows: ['ALLOW_USER_SRP_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH'],
			IdTokenValidity: 5,
			AccessTokenValidity: 5,
			RefreshTokenValidity: 1,
			TokenValidityUnits: {
				IdToken: 'minutes',
				AccessToken: 'minutes',
				RefreshToken: 'days',
			},
			EnableTokenRevocation: true,
			PreventUserExistenceErrors: 'ENABLED',
		};
		const updateClient = {
			service: 'CognitoIdentityServiceProvider',
			action: 'updateUserPoolClient',
			parameters: clientConfig,
			physicalResourceId: cr.PhysicalResourceId.of('client-urls'),
		};
		new cr.AwsCustomResource(this, 'ClientUrls', {
			onCreate: updateClient,
			onUpdate: updateClient,
			policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
				resources: [userPool.userPoolArn],
			}),
			installLatestAwsSdk: false,
		});

		new cdk.CfnOutput(this, 'DistributionDomain', {
			value: distribution.distributionDomainName,
		});
		new cdk.CfnOutput(this, 'DistributionId', {
			value: distribution.distributionId,
		});
		new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId });
		new cdk.CfnOutput(this, 'ClientId', { value: client.userPoolClientId });
		new cdk.CfnOutput(this, 'CognitoDomain', { value: cognitoDomainName });
		new cdk.CfnOutput(this, 'TestUsername', { value: TEST_USERNAME });
		new cdk.CfnOutput(this, 'TestUserPasswordSecret', {
			value: password.secretName,
		});
	}
}

const app = new cdk.App();
const stackName =
	app.node.tryGetContext('stackName') || 'cognito-at-edge-cff-test';
new CognitoAtEdgeCffTestStack(app, stackName, {
	// CloudFront Functions and KeyValueStore are managed in us-east-1.
	env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'us-east-1' },
});
// Optional tags on every resource: -c tags='{"key":"value"}' or "tags" in cdk.json / ~/.cdk.json.
const tags = app.node.tryGetContext('tags');
Object.entries(
	typeof tags === 'string' ? JSON.parse(tags) : tags || {},
).forEach(([key, value]) => cdk.Tags.of(app).add(key, String(value)));
