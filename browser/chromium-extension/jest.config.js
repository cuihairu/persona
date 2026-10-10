/** @type {import('jest').Config} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'jsdom',
    roots: ['<rootDir>/src'],
    testMatch: ['**/*.test.ts'],
    // 运行时源码的相对导入带 .js 后缀（浏览器 ESM 必需）；jest 下映射回 .ts
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1'
    },
    // TS 源码走 CommonJS 转译；与 tsconfig 的 isolatedModules/noEmit 约束解耦
    transform: {
        '^.+\\.ts$': [
            'ts-jest',
            {
                tsconfig: {
                    module: 'commonjs',
                    esModuleInterop: true,
                    target: 'es2020',
                    strict: true,
                    types: ['jest', 'chrome', 'node']
                }
            }
        ]
    }
};
