/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import js from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig([
	globalIgnores(['dist/', 'coverage/', 'CognitoAtEdgeTests/']),
	js.configs.recommended,
	{
		files: ['**/*.{js,mjs,cjs,ts,mts,cts}'],
		languageOptions: { globals: globals.node },
	},
	...tseslint.configs.recommended,
	{
		rules: {
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					args: 'all',
					argsIgnorePattern: '^_',
					caughtErrors: 'all',
					caughtErrorsIgnorePattern: '^_',
					destructuredArrayIgnorePattern: '^_',
					ignoreRestSiblings: true,
				},
			],
		},
	},
	{
		files: ['**/*.ts', '**/*.mts', '**/*.cts'],
		extends: [
			...tseslint.configs.recommendedTypeChecked,
			...tseslint.configs.strictTypeChecked,
		],
		languageOptions: {
			parserOptions: {
				project: './tsconfig.test.json',
			},
		},
		rules: {
			'@typescript-eslint/restrict-template-expressions': [
				'error',
				{ allowNumber: true },
			],
		},
	},
	eslintConfigPrettier,
]);
