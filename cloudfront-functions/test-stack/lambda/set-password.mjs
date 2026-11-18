// Custom resource: sets the test user's password from Secrets Manager at deploy time.
// Only the secret's ARN is in the template; the value never leaves this function.
import {
	SecretsManagerClient,
	GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import {
	CognitoIdentityProviderClient,
	AdminSetUserPasswordCommand,
} from '@aws-sdk/client-cognito-identity-provider';

export async function handler(event) {
	if (event.RequestType === 'Delete') {
		return { PhysicalResourceId: event.PhysicalResourceId };
	}
	const { UserPoolId, Username, SecretArn } = event.ResourceProperties;
	const secret = await new SecretsManagerClient({}).send(
		new GetSecretValueCommand({ SecretId: SecretArn }),
	);
	await new CognitoIdentityProviderClient({}).send(
		new AdminSetUserPasswordCommand({
			UserPoolId,
			Username,
			Password: secret.SecretString,
			Permanent: true,
		}),
	);
	return { PhysicalResourceId: `${UserPoolId}/${Username}/password` };
}
