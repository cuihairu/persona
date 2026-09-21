const baseConfig = require('./jest.config.cjs');

const config = { ...baseConfig };
// CI 覆盖率阈值：本地基线 70%，CI 按当前实测水平（lines ~95 / statements
// ~94 / functions ~94 / branches ~85）收紧并留 4 点余量，防漂移性回退。
config.coverageThreshold = {
  global: {
    branches: 80,
    functions: 90,
    lines: 90,
    statements: 90,
  },
};

module.exports = config;
