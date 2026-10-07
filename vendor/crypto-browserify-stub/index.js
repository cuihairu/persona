// Self-authored no-op stub — see package.json description.
// webpack/umi only require.resolve() this package for the node-polyfill
// alias map; nothing in this workspace imports node `crypto` in browser
// code, so this module is expected to never be loaded. Load = empty object.
module.exports = {};
