'use strict';

const utils = require('./utils');

const DEFAULT_MAX_DEPTH = 250;

const maxDepth = options => {
  const n = options && options.maxDepth;
  return typeof n === 'number' && n >= 0 ? Math.min(n, DEFAULT_MAX_DEPTH) : DEFAULT_MAX_DEPTH;
};

module.exports = (ast, options = {}) => {
  const stringify = (node, parent = {}, depth = 0) => {
    if (depth > maxDepth(options)) {
      throw new RangeError(`Pattern nesting depth exceeds options.maxDepth (${maxDepth(options)})`);
    }

    const invalidBlock = options.escapeInvalid && utils.isInvalidBrace(parent);
    const invalidNode = node.invalid === true && options.escapeInvalid === true;
    let output = '';

    if (node.value) {
      if ((invalidBlock || invalidNode) && utils.isOpenOrClose(node)) {
        return '\\' + node.value;
      }
      return node.value;
    }

    if (node.value) {
      return node.value;
    }

    if (node.nodes) {
      for (const child of node.nodes) {
        output += stringify(child, undefined, depth + 1);
      }
    }
    return output;
  };

  return stringify(ast);
};
