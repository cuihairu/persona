const baseConfig = require('./jest.config.cjs');

const config = { ...baseConfig };
// CI coverage thresholds: the local baseline is 70%, while CI is tightened to
// the currently measured level (lines ~95 / statements ~94 / functions ~94 /
// branches ~85) with 4 points of headroom, guarding against drift regressions.
config.coverageThreshold = {
  global: {
    branches: 80,
    functions: 90,
    lines: 90,
    statements: 90,
  },
};

module.exports = config;
