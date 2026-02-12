/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import js from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import { defineConfig, globalIgnores } from 'eslint/config';
import jestPlugin from 'eslint-plugin-jest';
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
		files: ['__tests__/**/*.ts'],
		...jestPlugin.configs['flat/all'],
		rules: {
			'jest/consistent-test-it': ['error', { fn: 'test' }],
			'jest/no-duplicate-hooks': 'error',
			'jest/no-test-return-statement': 'error',
			'jest/no-unneeded-async-expect-function': 'error',
			'jest/no-untyped-mock-factory': 'error',
			'jest/prefer-called-with': 'error',
			'jest/prefer-comparison-matcher': 'error',
			'jest/prefer-each': 'error',
			'jest/prefer-ending-with-an-expect': 'error',
			'jest/prefer-equality-matcher': 'error',
			'jest/prefer-expect-assertions': [
				'error',
				{ onlyFunctionsWithExpectInLoop: true },
			],
			'jest/prefer-hooks-in-order': 'error',
			'jest/prefer-hooks-on-top': 'error',
			'jest/prefer-jest-mocked': 'error',
			'jest/prefer-mock-promise-shorthand': 'error',
			'jest/prefer-mock-return-shorthand': 'error',
			'jest/prefer-spy-on': 'error',
			'jest/prefer-strict-equal': 'error',
			'jest/prefer-to-have-been-called': 'error',
			'jest/prefer-to-have-been-called-times': 'error',
			'jest/require-hook': 'error',
			'jest/require-to-throw-message': 'error',
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
