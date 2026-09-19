/** @type {import('jest').Config} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'jsdom',
    roots: ['<rootDir>/src'],
    testMatch: ['**/*.test.ts'],
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
