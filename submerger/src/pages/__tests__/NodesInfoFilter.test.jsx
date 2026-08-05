import { describe, expect, it } from 'vitest';

import { isInfoNode } from '../Nodes.jsx';

describe('节点管理信息节点过滤', () => {
  it.each([
    '放丢失官网:https://love.p6m6.com',
    '放丢失官网2:https://love2.p6m6.com',
    '防丢失官网:love.p6m6.com',
    '防失联官网:https://example.com',
  ])('过滤官网信息节点: %s', (name) => {
    expect(isInfoNode({ name })).toBe(true);
  });

  it.each([
    '官网香港01',
    '官网美国-01',
    '美国官网01 https://example.com',
    '香港 IEPL 01',
  ])('保留具有节点身份的名称: %s', (name) => {
    expect(isInfoNode({ name })).toBe(false);
  });
});
