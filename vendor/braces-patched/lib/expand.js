'use strict';

const fill = require('fill-range');
const stringify = require('./stringify');
const utils = require('./utils');

/**
 * Cap on AST nesting depth for the recursive walkers. Legitimate brace
 * patterns never nest past single digits; GHSA-vfj7-8cjw-p6xm crashes the
 * stack on adversarial patterns up to MAX_LENGTH (10k) characters deep.
 * Options may lower (not raise past the default) via `maxDepth`.
 */

const DEFAULT_MAX_DEPTH = 250;

const maxDepth = options => {
  const n = options && options.maxDepth;
  return typeof n === 'number' && n >= 0 ? Math.min(n, DEFAULT_MAX_DEPTH) : DEFAULT_MAX_DEPTH;
};

const append = (queue = '', stash = '', enclose = false) => {
  const result = [];

  queue = [].concat(queue);
  stash = [].concat(stash);

  if (!stash.length) return queue;
  if (!queue.length) {
    return enclose ? utils.flatten(stash).map(ele => `{${ele}}`) : stash;
  }

  for (const item of queue) {
    if (Array.isArray(item)) {
      for (const value of item) {
        result.push(append(value, stash, enclose));
      }
    } else {
      for (let ele of stash) {
        if (enclose === true && typeof ele === 'string') ele = `{${ele}}`;
        result.push(Array.isArray(ele) ? append(item, ele, enclose) : item + ele);
      }
    }
  }
  return utils.flatten(result);
};

const expand = (ast, options = {}) => {
  const rangeLimit = options.rangeLimit === undefined ? 1000 : options.rangeLimit;

  /**
   * Recursion depth through `walk` (and the nested arrays it feeds into
   * `append`) is bounded by AST nesting depth, so this single guard also
   * bounds the `append` recursion below.
   */

  const walk = (node, parent = {}, depth = 0) => {
    if (depth > maxDepth(options)) {
      throw new RangeError(`Pattern nesting depth exceeds options.maxDepth (${maxDepth(options)})`);
    }

    node.queue = [];

    let p = parent;
    let q = parent.queue;

    while (p.type !== 'brace' && p.type !== 'root' && p.parent) {
      p = p.parent;
      q = p.queue;
    }

    if (node.invalid || node.dollar) {
      q.push(append(q.pop(), stringify(node, options)));
      return;
    }

    if (node.type === 'brace' && node.invalid !== true && node.nodes.length === 2) {
      q.push(append(q.pop(), ['{}']));
      return;
    }

    if (node.nodes && node.ranges > 0) {
      const args = utils.reduce(node.nodes);

      if (utils.exceedsLimit(...args, options.step, rangeLimit)) {
        throw new RangeError('expanded array length exceeds range limit. Use options.rangeLimit to increase or disable the limit.');
      }

      let range = fill(...args, options);
      if (range.length === 0) {
        range = stringify(node, options);
      }

      q.push(append(q.pop(), range));
      node.nodes = [];
      return;
    }

    const enclose = utils.encloseBrace(node);
    let queue = node.queue;
    let block = node;

    while (block.type !== 'brace' && block.type !== 'root' && block.parent) {
      block = block.parent;
      queue = block.queue;
    }

    for (let i = 0; i < node.nodes.length; i++) {
      const child = node.nodes[i];

      if (child.type === 'comma' && node.type === 'brace') {
        if (i === 1) queue.push('');
        queue.push('');
        continue;
      }

      if (child.type === 'close') {
        q.push(append(q.pop(), queue, enclose));
        continue;
      }

      if (child.value && child.type !== 'open') {
        queue.push(append(queue.pop(), child.value));
        continue;
      }

      if (child.nodes) {
        walk(child, node, depth + 1);
      }
    }

    return queue;
  };

  return utils.flatten(walk(ast));
};

module.exports = expand;
