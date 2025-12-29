const baseConfig = require('./jest.config.cjs');

const config = { ...baseConfig };
delete config.coverageThreshold;

module.exports = config;
