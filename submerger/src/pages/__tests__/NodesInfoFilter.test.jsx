import { describe, expect, it } from 'vitest';

import {
  getNodeIpProperty,
  getNodeIpSource,
  isInfoNode,
  isNodeIpPropertyUntested,
  isNodeIpSourceUntested,
} from '../Nodes.jsx';

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

describe('节点 IP 筛选字段', () => {
  it('优先读取持久化 IP 画像中的来源和属性', () => {
    expect(getNodeIpSource({ ip_profile: { ip_source: 'native' }, ip_source: 'broadcast' })).toBe('native');
    expect(getNodeIpProperty({ ip_profile: { network_type: 'residential' }, network_type: 'datacenter' })).toBe('residential');
  });

  it('兼容扁平化节点字段', () => {
    expect(getNodeIpSource({ ip_source: 'broadcast' })).toBe('broadcast');
    expect(getNodeIpProperty({ network_type: 'datacenter' })).toBe('datacenter');
  });

  it('将缺少 IP 来源或属性的节点归入未检测', () => {
    expect(isNodeIpSourceUntested({})).toBe(true);
    expect(isNodeIpSourceUntested({ ip_profile: { ip_source: null } })).toBe(true);
    expect(isNodeIpPropertyUntested({})).toBe(true);
    expect(isNodeIpPropertyUntested({ ip_profile: { network_type: '' } })).toBe(true);
  });

  it('已有检测结果的节点不归入未检测', () => {
    expect(isNodeIpSourceUntested({ ip_source: 'native' })).toBe(false);
    expect(isNodeIpSourceUntested({ ip_profile: { ip_source: 'broadcast' } })).toBe(false);
    expect(isNodeIpPropertyUntested({ network_type: 'residential' })).toBe(false);
    expect(isNodeIpPropertyUntested({ ip_profile: { network_type: 'datacenter' } })).toBe(false);
  });
});
