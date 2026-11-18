// Custom resource: copies the user pool's public keys (JWKS) into the KeyValueStore the
// CloudFront Function reads, one key per kid: 'jwk.<kid>' -> { "n": ..., "e": ... }.
// A KVS value is 1 KB at most, so the whole JWKS does not fit in one key.
import '@aws-sdk/signature-v4a'; // the KVS data plane is signed with SigV4a
import {
	CloudFrontKeyValueStoreClient,
	DescribeKeyValueStoreCommand,
	UpdateKeysCommand,
} from '@aws-sdk/client-cloudfront-keyvaluestore';

const kvs = new CloudFrontKeyValueStoreClient({});

export async function handler(event) {
	if (event.RequestType === 'Delete') {
		return { PhysicalResourceId: event.PhysicalResourceId };
	}
	const { KvsARN, JwksUrl } = event.ResourceProperties;
	const response = await fetch(JwksUrl);
	if (!response.ok) {
		throw new Error(`JWKS ${JwksUrl} returned ${response.status}`);
	}
	const { keys } = await response.json();
	const puts = keys.map((k) => ({
		Key: `jwk.${k.kid}`,
		Value: JSON.stringify({ n: k.n, e: k.e }),
	}));
	const { ETag } = await kvs.send(new DescribeKeyValueStoreCommand({ KvsARN }));
	await kvs.send(new UpdateKeysCommand({ KvsARN, IfMatch: ETag, Puts: puts }));
	console.log(`wrote ${puts.length} keys`);
	return { PhysicalResourceId: `${KvsARN}/jwks` };
}
