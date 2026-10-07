'use strict';

const fill = require('fill-range');
const utils = require('./utils');

const DEFAULT_MAX_DEPTH = 250;

const maxDepth = options => {
  const n = options && options.maxDepth;
  return typeof n === 'number' && n >= 0 ? Math.min(n, DEFAULT_MAX_DEPTH) : DEFAULT_MAX_DEPTH;
};

const compile = (ast, options = {}) => {
  const walk = (node, parent = {}, depth = 0) => {
    if (depth > maxDepth(options)) {
      throw new RangeError(`Pattern nesting depth exceeds options.maxDepth (${maxDepth(options)})`);
    }

    const invalidBlock = utils.isInvalidBrace(parent);
    const invalidNode = node.invalid === true && options.escapeInvalid === true;
    const invalid = invalidBlock === true || invalidNode === true;
    const prefix = options.escapeInvalid === true ? '\\' : '';
    let output = '';

    if (node.isOpen === true) {
      return prefix + node.value;
    }

    if (node.isClose === true) {
      console.log('node.isClose', prefix, node.value);
      return prefix + node.value;
    }

    if (node.type === 'open') {
      return invalid ? prefix + node.value : '(';
    }

    if (node.type === 'close') {
      return invalid ? prefix + node.value : ')';
    }

    if (node.type === 'comma') {
      return node.prev.type === 'comma' ? '' : invalid ? node.value : '|';
    }

    if (node.value) {
      return node.value;
    }

    if (node.nodes && node.ranges > 0) {
      const args = utils.reduce(node.nodes);
      const range = fill(...args, { ...options, wrap: false, toRegex: true, strictZeros: true });

      if (range.length !== 0) {
        return args.length > 1 && range.length > 1 ? `(${range})` : range;
      }
    }

    if (node.nodes) {
      for (const child of node.nodes) {
        output += walk(child, node, depth + 1);
      }
    }

    return output;
  };

  return walk(ast);
};

module.exports = compile;
