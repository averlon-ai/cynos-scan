import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import prettierConfig from 'eslint-config-prettier';
import prettierPlugin from 'eslint-plugin-prettier';
import regexpPlugin from 'eslint-plugin-regexp';

export default [
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/coverage/**',
      '**/*.min.js',
      '**/bun.lockb',
      '**/.github/**',
      '**/test/terraform/**',
      '**/*.test.ts',
    ],
  },
  {
    files: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      prettier: prettierPlugin,
      regexp: regexpPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      'prettier/prettier': 'error',
      // A regex that backtracks super-linearly on input we don't control (a remote URL, a path, a
      // setting) can stall a scan: CodeQL flagged one in the public repository (js/polynomial-redos),
      // and this repository has no CodeQL. These two rules catch the same patterns at lint time.
      'regexp/no-super-linear-backtracking': 'error',
      'regexp/no-super-linear-move': 'error',
    },
  },
  prettierConfig,
];

