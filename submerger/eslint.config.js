import js from '@eslint/js'
import reactHooks from 'eslint-plugin-react-hooks'
import globals from 'globals'

export default [
  { ignores: ['dist', 'node_modules', 'scripts'] },
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      // 只启用核心 hooks 规则；v6 新增的 immutability / set-state-in-effect /
      // static-components 对存量代码噪声过大，待后续重构时逐步启用。
      'react-hooks/rules-of-hooks': 'error',
      // 老代码依赖数组欠账较多，先以告警暴露，新增代码应修复到零告警。
      'react-hooks/exhaustive-deps': 'warn',
      'no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
    },
  },
]
