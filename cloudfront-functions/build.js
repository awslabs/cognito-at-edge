/* eslint-disable @typescript-eslint/no-require-imports */
'use strict';

// Generates the CloudFront Functions code from viewer-request.js and a settings object.
//   node cloudfront-functions/build.js settings.json > function.js
// The output is one file for runtime cloudfront-js-2.0. Comment lines and indentation are
// removed so the code stays under the 10 KB function size limit.

const fs = require('fs');
const path = require('path');

const MAX_FUNCTION_BYTES = 10240;
const TEMPLATE = path.join(__dirname, 'viewer-request.js');

const REQUIRED = [
	'region',
	'userPoolId',
	'userPoolAppId',
	'userPoolDomain',
	'cognitoOriginId',
];
const DEFAULTS = {
	tokenUse: 'id',
	parseAuthPath: '/parseauth',
	logoutPath: '',
	logoutRedirectUri: '/',
	cognitoLogout: false,
	jwksOriginId: '',
	cookieExpirationDays: 365,
	cookiePath: '/',
	cookieDomain: '',
	httpOnly: false,
	sameSite: '',
};

// Syntax that cloudfront-js-2.0 accepts when the function is published but rejects at run time
// (every request is then a 503), or rejects at publish time.
const UNSUPPORTED_SYNTAX = [
	{ name: 'for...of', pattern: /\bfor\s*\([^)]*\sof\s/ },
	{ name: 'optional chaining (?.)', pattern: /\?\.[A-Za-z_$[(]/ },
	{ name: 'spread (...)', pattern: /\.\.\.[A-Za-z_$[{(]/ },
	{ name: 'await inside call arguments', pattern: /[(,]\s*await\s/ },
];

function validate(settings) {
	if (!settings || typeof settings !== 'object') {
		throw new Error('Expected settings to be an object');
	}
	REQUIRED.forEach((name) => {
		if (typeof settings[name] !== 'string' || !settings[name]) {
			throw new Error(`Expected settings.${name} to be a non-empty string`);
		}
	});
	if (settings.tokenUse !== 'id' && settings.tokenUse !== 'access') {
		throw new Error('Expected settings.tokenUse to be id || access');
	}
	['parseAuthPath', 'logoutPath', 'cookiePath'].forEach((name) => {
		if (settings[name] && !/^\/[^\s?#]*$/.test(settings[name])) {
			throw new Error(
				`Expected settings.${name} to be a path starting with "/"`,
			);
		}
	});
	if (
		!settings.parseAuthPath ||
		settings.parseAuthPath === settings.logoutPath
	) {
		throw new Error(
			'Expected settings.parseAuthPath to be set and differ from logoutPath',
		);
	}
	if (!['', 'Strict', 'Lax', 'None'].includes(settings.sameSite)) {
		throw new Error('Expected settings.sameSite to be a Strict || Lax || None');
	}
	if (
		typeof settings.cookieExpirationDays !== 'number' ||
		settings.cookieExpirationDays <= 0
	) {
		throw new Error(
			'Expected settings.cookieExpirationDays to be a positive number',
		);
	}
}

function assertSupported(code) {
	UNSUPPORTED_SYNTAX.forEach(({ name, pattern }) => {
		if (pattern.test(code)) {
			throw new Error(
				`Function code uses ${name}, which cloudfront-js-2.0 rejects`,
			);
		}
	});
}

function minify(code) {
	return code
		.split('\n')
		.map((line) => line.trim())
		.filter(
			(line) => line && !line.startsWith('//') && !/^\/\*.*\*\/$/.test(line),
		)
		.reduce((out, line) => {
			// No line break needed after an opening bracket or comma, or before a closing
			// bracket or a continuation operator.
			const join = /[({[,]$/.test(out) || /^([)}\].?:+]|&&|\|\|)/.test(line);
			return out ? out + (join ? '' : '\n') + line : line;
		}, '');
}

/**
 * The function code for the given settings.
 * @param {object} settings see cloudfront-functions/README.md
 * @returns {string} CloudFront Functions code, cloudfront-js-2.0
 */
function buildFunction(settings) {
	const merged = Object.assign({}, DEFAULTS, settings);
	validate(merged);
	const config = {};
	Object.keys(DEFAULTS)
		.concat(REQUIRED)
		.forEach((name) => {
			config[name] = merged[name];
		});
	const template = fs.readFileSync(TEMPLATE, 'utf8');
	const code = minify(template).replace('__CONFIG__', JSON.stringify(config));
	assertSupported(code);
	const size = Buffer.byteLength(code);
	if (size > MAX_FUNCTION_BYTES) {
		throw new Error(
			`Function code is ${size} bytes, over the ${MAX_FUNCTION_BYTES} byte limit`,
		);
	}
	return code;
}

module.exports = { buildFunction, assertSupported, MAX_FUNCTION_BYTES };

if (require.main === module) {
	const file = process.argv[2];
	if (!file) {
		process.stderr.write(
			'usage: node cloudfront-functions/build.js settings.json > function.js\n',
		);
		process.exit(2);
	}
	process.stdout.write(
		buildFunction(JSON.parse(fs.readFileSync(file, 'utf8'))) + '\n',
	);
}
