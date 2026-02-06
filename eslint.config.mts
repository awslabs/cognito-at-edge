import js from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig([
	globalIgnores(['dist/', 'coverage/', 'CognitoAtEdgeTests/']),
	{
		files: ['**/*.{js,mjs,cjs,ts,mts,cts}'],
		plugins: { js },
		extends: ['js/recommended'],
		languageOptions: { globals: globals.node },
	},
	...tseslint.configs.recommended,
	{
		rules: {
			// Temporary disable while migrating to newer eslint version
			'@typescript-eslint/no-unused-vars': 'off',
		},
	},
	{
		files: ['**/*.ts', '**/*.mts', '**/*.cts'],
		extends: [
			// ...tseslint.configs.recommendedTypeChecked,
			// ...tseslint.configs.strictTypeChecked,
		],
		languageOptions: {
			parserOptions: {
				project: './tsconfig.test.json',
			},
		},
	},
	eslintConfigPrettier,
]);
