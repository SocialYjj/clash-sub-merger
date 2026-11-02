import { describe, expect, it } from 'vitest';

import { buildEditedNode, getTransportOptions } from '../NodeEditModal.jsx';

const baseForm = {
  name: 'Edited',
  type: 'vless',
  server: 'example.com',
  port: 443,
  uuid: '11111111-1111-1111-1111-111111111111',
  username: '',
  password: '',
  alterId: 0,
  cipher: 'auto',
  flow: '',
  encryption: 'none',
  network: 'tcp',
  host: '',
  path: '',
  grpcServiceName: '',
  xhttpMode: 'auto',
  security: '',
  sni: '',
  clientFingerprint: '',
  certificateFingerprint: '',
  alpn: '',
  allowInsecure: false,
  publicKey: '',
  shortId: '',
  muxEnabled: false,
  obfs: '',
  obfsPassword: '',
  congestionController: 'bbr',
  udpRelayMode: 'native',
};

describe('NodeEditModal node serialization', () => {
  it('limits transport choices by Mihomo protocol support', () => {
    expect(getTransportOptions('vless')).toEqual([
      'tcp', 'ws', 'httpupgrade', 'http', 'h2', 'grpc', 'xhttp',
    ]);
    expect(getTransportOptions('vmess')).not.toContain('xhttp');
    expect(getTransportOptions('trojan')).toEqual(['tcp', 'ws', 'httpupgrade', 'grpc']);
    expect(getTransportOptions('hysteria2')).toEqual([]);
  });

  it('preserves Reality ALPN and spider-x during editing', () => {
    const node = {
      name: 'Reality',
      type: 'vless',
      server: 'example.com',
      port: 443,
      uuid: baseForm.uuid,
      tls: true,
      alpn: ['h2'],
      'reality-opts': {
        'public-key': 'public-key',
        'short-id': 'abcd',
        'spider-x': '/unsupported',
        'support-x25519mlkem768': true,
      },
    };
    const saved = buildEditedNode(node, {
      ...baseForm,
      security: 'reality',
      sni: 'www.example.com',
      alpn: 'h3,h2',
      publicKey: 'public-key',
      shortId: 'abcd',
    });

    expect(saved.alpn).toEqual(['h3', 'h2']);
    expect(saved['reality-opts']).toEqual({
      'public-key': 'public-key',
      'short-id': 'abcd',
      'spider-x': '/unsupported',
      'support-x25519mlkem768': true,
    });
  });

  it('removes unsupported gRPC mode and authority while preserving supported options', () => {
    const node = {
      name: 'gRPC',
      type: 'vless',
      server: 'example.com',
      port: 443,
      uuid: baseForm.uuid,
      network: 'grpc',
      'grpc-opts': {
        mode: 'multi',
        authority: 'unsupported.example.com',
        'grpc-service-name': 'old',
        'ping-interval': 30,
      },
    };
    const saved = buildEditedNode(node, {
      ...baseForm,
      network: 'grpc',
      grpcServiceName: 'new-service',
    });

    expect(saved['grpc-opts']).toEqual({
      'grpc-service-name': 'new-service',
      'ping-interval': 30,
    });
  });

  it('cleans transport, Reality, authentication and protocol-only fields after protocol switch', () => {
    const node = {
      name: 'Old VLESS',
      type: 'vless',
      server: 'example.com',
      port: 443,
      uuid: baseForm.uuid,
      flow: 'xtls-rprx-vision',
      encryption: 'none',
      network: 'ws',
      'ws-opts': { path: '/ws', headers: { Host: 'cdn.example.com' } },
      tls: true,
      servername: 'www.example.com',
      alpn: ['h2'],
      'reality-opts': { 'public-key': 'key', 'short-id': 'abcd', 'spider-x': '/' },
      smux: { enabled: true },
    };
    const saved = buildEditedNode(node, {
      ...baseForm,
      type: 'hysteria2',
      password: 'hy2-password',
      network: 'ws',
      security: 'tls',
      sni: 'hy2.example.com',
      alpn: 'h3',
      obfs: 'salamander',
      obfsPassword: 'obfs-password',
    });

    expect(saved).toMatchObject({
      type: 'hysteria2',
      password: 'hy2-password',
      sni: 'hy2.example.com',
      alpn: ['h3'],
      obfs: 'salamander',
      'obfs-password': 'obfs-password',
    });
    for (const field of [
      'uuid', 'flow', 'encryption', 'network', 'ws-opts', 'grpc-opts',
      'reality-opts', 'servername', 'smux',
    ]) {
      expect(saved).not.toHaveProperty(field);
    }
  });

  it('never echoes backend-managed metadata that the update endpoint rejects', () => {
    const node = {
      name: 'US-tailscale',
      type: 'vless',
      server: '2001:550:a20::16c',
      port: 10203,
      uuid: baseForm.uuid,
      enabled: true,
      display_name: 'US-tailscale',
      index: 3,
      sourceType: 'custom',
      exit_ip: '2001:550:a20::16c',
      ip_profile: { exit_ip: '2001:550:a20::16c', fraud_score: 12, ip_source: 'native' },
      geoip: { country: 'US' },
      region: { code: 'US' },
      city: 'Los Angeles',
      last_latency: 210,
      last_speed: 12.5,
    };

    const saved = buildEditedNode(node, {
      ...baseForm,
      server: '203.0.113.10',
      port: 10203,
    });

    for (const field of [
      'enabled', 'display_name', 'index', 'sourceType', 'exit_ip', 'ip_profile',
      'geoip', 'region', 'city', 'last_latency', 'last_speed',
    ]) {
      expect(saved).not.toHaveProperty(field);
    }
    expect(saved.server).toBe('203.0.113.10');
    expect(saved.port).toBe(10203);
  });

  it('does not silently keep an unsupported transport for a protocol', () => {
    const saved = buildEditedNode(
      { name: 'Trojan', type: 'trojan', server: 'example.com', port: 443, password: 'secret' },
      { ...baseForm, type: 'trojan', password: 'secret', network: 'xhttp' },
    );

    expect(saved).not.toHaveProperty('network');
    expect(saved).not.toHaveProperty('xhttp-opts');
  });
});
