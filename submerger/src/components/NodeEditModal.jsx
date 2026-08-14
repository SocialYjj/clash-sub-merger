import React, { useState, useEffect } from 'react';
import { X, Save, Server } from 'lucide-react';
import request from '../utils/request';

const API_BASE = '/api';


const TRANSPORT_OPTIONS = {
    vless: ['tcp', 'ws', 'httpupgrade', 'http', 'h2', 'grpc', 'xhttp'],
    vmess: ['tcp', 'ws', 'httpupgrade', 'http', 'h2', 'grpc'],
    trojan: ['tcp', 'ws', 'httpupgrade', 'grpc'],
};

const EDITABLE_PROTOCOLS = [
    'vless', 'vmess', 'trojan', 'ss', 'socks5', 'http',
    'hysteria2', 'tuic', 'anytls',
];

const REALITY_PROTOCOLS = new Set(['vless', 'vmess', 'trojan']);
const TLS_PROTOCOLS = new Set([
    'vless', 'vmess', 'trojan', 'http',
    'hysteria2', 'tuic', 'anytls',
]);

function normalizeProtocol(value) {
    return String(value || '').trim().toLowerCase();
}

function transportValue(node) {
    const network = String(node?.network || 'tcp').trim().toLowerCase();
    if (network === 'ws' && node?.['ws-opts']?.['v2ray-http-upgrade']) {
        return 'httpupgrade';
    }
    return network;
}

function setOrDelete(target, key, value) {
    if (value === undefined || value === null || value === '') {
        delete target[key];
    } else {
        target[key] = value;
    }
}

function replaceHostHeader(headers, host) {
    const normalized = headers && typeof headers === 'object' && !Array.isArray(headers)
        ? { ...headers }
        : {};
    for (const key of Object.keys(normalized)) {
        if (key.toLowerCase() === 'host') delete normalized[key];
    }
    if (host) normalized.Host = host;
    return normalized;
}

export function getTransportOptions(type) {
    return TRANSPORT_OPTIONS[normalizeProtocol(type)] || [];
}

export function buildEditedNode(node, formData) {
    const metadataFields = new Set([
        'id', 'link', 'enabled', 'display_name', 'index', 'last_latency',
        'last_latency_time', 'last_speed', 'last_peak_speed', 'last_speed_time',
        'last_peak_speed_time', 'exit_ip', 'geoip', 'region', 'city',
        'sourceType', 'sourceName',
    ]);
    const nodeObj = Object.fromEntries(
        Object.entries(node || {}).filter(([key]) => !metadataFields.has(key) && !key.startsWith('_'))
    );
    const originalType = normalizeProtocol(node?.type);
    const type = normalizeProtocol(formData.type) || 'vless';
    const typeChanged = originalType !== type;

    for (const key of [
        'uuid', 'username', 'password', 'alterId', 'cipher', 'method',
        'flow', 'encryption', 'obfs', 'obfs-password',
        'congestion-controller', 'udp-relay-mode', 'smux',
        'header-type', 'ws-opts', 'grpc-opts', 'h2-opts', 'http-opts',
        'xhttp-opts', 'xhttp-mode', 'host', 'path', 'seed', 'mtu',
        'tls', 'sni', 'servername', 'reality-opts', 'client-fingerprint',
        'fingerprint', 'alpn', 'skip-cert-verify',
    ]) {
        delete nodeObj[key];
    }
    if (typeChanged) {
        for (const key of [
            'network', 'plugin', 'plugin-opts', 'token', 'auth', 'auth-str',
            'private-key', 'public-key', 'ip', 'ports', 'mport',
            'up', 'down', 'up-speed', 'down-speed',
        ]) {
            delete nodeObj[key];
        }
    }

    Object.assign(nodeObj, {
        name: formData.name,
        type,
        server: formData.server,
        port: parseInt(formData.port, 10) || 443,
    });

    if (['vless', 'vmess', 'tuic'].includes(type)) nodeObj.uuid = formData.uuid || '';
    if (type === 'vmess') {
        nodeObj.alterId = parseInt(formData.alterId, 10) || 0;
        nodeObj.cipher = formData.cipher || 'auto';
    }
    if (['trojan', 'ss', 'hysteria2', 'tuic', 'anytls'].includes(type)) {
        nodeObj.password = formData.password || '';
    }
    if (['socks5', 'http'].includes(type)) {
        setOrDelete(nodeObj, 'username', String(formData.username || '').trim());
        setOrDelete(nodeObj, 'password', String(formData.password || ''));
    }
    if (type === 'ss') nodeObj.cipher = formData.cipher || 'aes-256-gcm';
    if (type === 'vless') {
        setOrDelete(nodeObj, 'flow', formData.flow);
        setOrDelete(nodeObj, 'encryption', String(formData.encryption || '').trim() || 'none');
    }

    const transportOptions = getTransportOptions(type);
    const requestedTransport = String(formData.network || 'tcp').trim().toLowerCase();
    const network = transportOptions.includes(requestedTransport) ? requestedTransport : 'tcp';
    const sameTransport = !typeChanged && transportValue(node) === network;
    if (transportOptions.length > 0) {
        if (network !== 'tcp') nodeObj.network = network === 'httpupgrade' ? 'ws' : network;
        else delete nodeObj.network;

        if (network === 'ws' || network === 'httpupgrade') {
            const opts = sameTransport && node?.['ws-opts'] && typeof node['ws-opts'] === 'object'
                ? { ...node['ws-opts'] }
                : {};
            delete opts.path;
            opts.headers = replaceHostHeader(opts.headers, formData.host);
            if (Object.keys(opts.headers).length === 0) delete opts.headers;
            setOrDelete(opts, 'path', formData.path);
            if (network === 'httpupgrade') opts['v2ray-http-upgrade'] = true;
            else delete opts['v2ray-http-upgrade'];
            nodeObj['ws-opts'] = opts;
        } else if (network === 'grpc') {
            const opts = sameTransport && node?.['grpc-opts'] && typeof node['grpc-opts'] === 'object'
                ? { ...node['grpc-opts'] }
                : {};
            delete opts.mode;
            delete opts.authority;
            setOrDelete(opts, 'grpc-service-name', formData.grpcServiceName);
            nodeObj['grpc-opts'] = opts;
        } else if (network === 'h2') {
            const opts = sameTransport && node?.['h2-opts'] && typeof node['h2-opts'] === 'object'
                ? { ...node['h2-opts'] }
                : {};
            setOrDelete(opts, 'host', formData.host ? [formData.host] : '');
            setOrDelete(opts, 'path', formData.path);
            nodeObj['h2-opts'] = opts;
        } else if (network === 'http') {
            const opts = sameTransport && node?.['http-opts'] && typeof node['http-opts'] === 'object'
                ? { ...node['http-opts'] }
                : {};
            setOrDelete(opts, 'path', formData.path ? [formData.path] : '');
            opts.headers = replaceHostHeader(opts.headers, formData.host ? [formData.host] : '');
            if (Object.keys(opts.headers).length === 0) delete opts.headers;
            nodeObj['http-opts'] = opts;
        } else if (network === 'xhttp') {
            const opts = sameTransport && node?.['xhttp-opts'] && typeof node['xhttp-opts'] === 'object'
                ? { ...node['xhttp-opts'] }
                : {};
            setOrDelete(opts, 'mode', formData.xhttpMode);
            setOrDelete(opts, 'path', formData.path);
            setOrDelete(opts, 'host', formData.host);
            if (Object.keys(opts).length > 0) nodeObj['xhttp-opts'] = opts;
        }
    } else if (typeChanged) {
        delete nodeObj.network;
    }

    const requestedSecurity = String(formData.security || '').trim().toLowerCase();
    const security = requestedSecurity === 'reality' && !REALITY_PROTOCOLS.has(type)
        ? 'tls'
        : requestedSecurity;
    const usesSniField = ['trojan', 'hysteria2', 'tuic', 'anytls'].includes(type);
    if (security === 'tls' && TLS_PROTOCOLS.has(type)) {
        nodeObj.tls = true;
        setOrDelete(nodeObj, usesSniField ? 'sni' : 'servername', formData.sni);
        setOrDelete(nodeObj, 'client-fingerprint', formData.clientFingerprint);
        setOrDelete(nodeObj, 'fingerprint', formData.certificateFingerprint);
        const alpn = String(formData.alpn || '').split(',').map(value => value.trim()).filter(Boolean);
        if (alpn.length > 0) nodeObj.alpn = alpn;
        if (formData.allowInsecure) nodeObj['skip-cert-verify'] = true;
    } else if (security === 'reality' && REALITY_PROTOCOLS.has(type)) {
        nodeObj.tls = true;
        const originalReality = !typeChanged && node?.['reality-opts'] && typeof node['reality-opts'] === 'object'
            ? { ...node['reality-opts'] }
            : {};
        setOrDelete(originalReality, 'public-key', formData.publicKey);
        setOrDelete(originalReality, 'short-id', formData.shortId);
        nodeObj['reality-opts'] = originalReality;
        setOrDelete(nodeObj, usesSniField ? 'sni' : 'servername', formData.sni);
        setOrDelete(nodeObj, 'client-fingerprint', formData.clientFingerprint);
        setOrDelete(nodeObj, 'fingerprint', formData.certificateFingerprint);
        const alpn = String(formData.alpn || '').split(',').map(value => value.trim()).filter(Boolean);
        if (alpn.length > 0) nodeObj.alpn = alpn;
    }

    if (formData.muxEnabled && ['vless', 'vmess', 'trojan'].includes(type)) {
        nodeObj.smux = { enabled: true };
    }
    if (type === 'hysteria2') {
        setOrDelete(nodeObj, 'obfs', formData.obfs);
        setOrDelete(nodeObj, 'obfs-password', formData.obfsPassword);
    }
    if (type === 'tuic') {
        setOrDelete(nodeObj, 'congestion-controller', formData.congestionController);
        setOrDelete(nodeObj, 'udp-relay-mode', formData.udpRelayMode);
    }

    return nodeObj;
}

// Field component - V2RayN style (label on left, input on right, single column)
function Field({ label, children }) {
    return (
        <div className="flex items-center gap-4 py-1.5">
            <label className="text-sm text-gray-400 w-40 flex-shrink-0">{label}</label>
            <div className="flex-1">{children}</div>
        </div>
    );
}

// Section divider
function Divider({ title }) {
    return (
        <div className="flex items-center gap-3 py-3 mt-2">
            <div className="h-px bg-gray-700 flex-1" />
            <span className="text-xs text-gray-500 font-medium">{title}</span>
            <div className="h-px bg-gray-700 flex-1" />
        </div>
    );
}

export default function NodeEditModal({ node, onClose, onSave, showToast }) {
    const [formData, setFormData] = useState({});
    const [saving, setSaving] = useState(false);

    const isCustomNode = node?.sourceType === 'custom';

    useEffect(() => {
        if (node) {
            const wsOpts = node['ws-opts'] || {};
            const grpcOpts = node['grpc-opts'] || {};
            const realityOpts = node['reality-opts'] || {};
            const h2Opts = node['h2-opts'] || {};
            const xhttpOpts = node['xhttp-opts'] || {};
            const httpOpts = node['http-opts'] || {};
            const currentTransport = transportValue(node);
            const httpHost = httpOpts.headers?.Host;

            setFormData({
                // Basic
                name: node.name || '',
                type: normalizeProtocol(node.type) || 'vless',
                server: node.server || '',
                port: node.port || 443,
                // Auth
                uuid: node.uuid || '',
                username: node.username || '',
                password: node.password || '',
                alterId: node.alterId || 0,
                // VLESS specific
                flow: node.flow || '',
                encryption: node.encryption || 'none',
                // Transport
                network: currentTransport,
                host: wsOpts.headers?.Host
                    || (Array.isArray(h2Opts.host) ? h2Opts.host[0] : h2Opts.host)
                    || (Array.isArray(httpHost) ? httpHost[0] : httpHost)
                    || xhttpOpts.host || node.host || '',
                path: wsOpts.path
                    || (Array.isArray(httpOpts.path) ? httpOpts.path[0] : httpOpts.path)
                    || h2Opts.path || xhttpOpts.path || node.path || '',
                grpcServiceName: grpcOpts['grpc-service-name'] || '',
                xhttpMode: xhttpOpts.mode || node['xhttp-mode'] || 'auto',
                // TLS
                security: node['reality-opts'] ? 'reality' : (node.tls ? 'tls' : ''),
                sni: node.sni || node.servername || '',
                // Keep the uTLS browser fingerprint and the server certificate
                // pin separate. They are both called "fingerprint" in some
                // clients but have different Mihomo fields and semantics.
                clientFingerprint: node['client-fingerprint'] || '',
                certificateFingerprint: node.fingerprint || '',
                alpn: Array.isArray(node.alpn) ? node.alpn.join(',') : (node.alpn || ''),
                allowInsecure: node['skip-cert-verify'] || false,
                // Reality
                publicKey: realityOpts['public-key'] || '',
                shortId: realityOpts['short-id'] || '',
                // Mux
                muxEnabled: node.smux?.enabled || false,
                // SS
                cipher: node.cipher || node.method || 'auto',
                // Hysteria2
                obfs: node.obfs || '',
                obfsPassword: node['obfs-password'] || '',
                // TUIC
                congestionController: node['congestion-controller'] || 'bbr',
                udpRelayMode: node['udp-relay-mode'] || 'native',
            });
        }
    }, [node]);

    const handleChange = (field, value) => {
        setFormData(prev => {
            if (field === 'type') {
                const type = normalizeProtocol(value);
                const transportOptions = getTransportOptions(type);
                const network = transportOptions.includes(prev.network)
                    ? prev.network
                    : (transportOptions[0] || 'tcp');
                const security = prev.security === 'reality' && !REALITY_PROTOCOLS.has(type)
                    ? (TLS_PROTOCOLS.has(type) ? 'tls' : '')
                    : (TLS_PROTOCOLS.has(type) ? prev.security : '');
                return {
                    ...prev,
                    type,
                    network,
                    security,
                    host: '',
                    path: '',
                    grpcServiceName: '',
                    xhttpMode: 'auto',
                    flow: '',
                    encryption: type === 'vless' ? 'none' : '',
                    obfs: '',
                    obfsPassword: '',
                    congestionController: 'bbr',
                    udpRelayMode: 'native',
                    muxEnabled: false,
                };
            }
            if (field === 'network') {
                return {
                    ...prev,
                    network: value,
                    host: '',
                    path: '',
                    grpcServiceName: '',
                    xhttpMode: 'auto',
                };
            }
            if (field === 'security') {
                return {
                    ...prev,
                    security: value,
                    publicKey: value === 'reality' ? prev.publicKey : '',
                    shortId: value === 'reality' ? prev.shortId : '',
                    allowInsecure: value === 'tls' ? prev.allowInsecure : false,
                };
            }
            return { ...prev, [field]: value };
        });
    };

    const buildNodeObject = () => buildEditedNode(node, formData);

    const handleSave = async () => {
        if (!isCustomNode) {
            showToast?.('订阅节点仅支持查看', 'warning');
            return;
        }
        setSaving(true);
        try {
            await request.put(`${API_BASE}/custom-nodes/${node.id}/full`, { node: buildNodeObject() });
            showToast?.('节点已更新');
            if (onSave) await onSave();
            onClose();
        } catch (err) {
            showToast?.('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
        } finally {
            setSaving(false);
        }
    };

    if (!node) return null;

    const inputClass = (disabled) => `w-full px-3 py-1.5 bg-gray-700 border border-gray-600 rounded text-white text-sm ${disabled ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500 focus:outline-none'}`;
    const selectClass = (disabled) => `w-full px-3 py-1.5 bg-gray-700 border border-gray-600 rounded text-white text-sm ${disabled ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500 focus:outline-none'}`;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
            <div className="bg-gray-800 rounded-xl w-full max-w-xl max-h-[90vh] flex flex-col">
                {/* Header */}
                <div className="p-4 border-b border-gray-700 flex items-center justify-between flex-shrink-0">
                    <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${isCustomNode ? 'bg-blue-500/20 text-blue-400' : 'bg-gray-600/20 text-gray-400'}`}>
                            <Server size={20} />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white">{formData.type?.toUpperCase() || 'VLESS'}</h2>
                            <p className="text-xs text-gray-400">{isCustomNode ? '编辑节点' : '节点详情'}</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white"><X size={24} /></button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-4">
                    {/* Configuration */}
                    <Divider title="配置项" />
                    
                    <Field label="协议类型 (type)">
                        <select value={formData.type} onChange={(e) => handleChange('type', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                            {EDITABLE_PROTOCOLS.map(type => <option key={type} value={type}>{type}</option>)}
                        </select>
                    </Field>

                    <Field label="别名 (remarks)">
                        <input type="text" value={formData.name} onChange={(e) => handleChange('name', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                    </Field>
                    
                    <Field label="地址 (address)">
                        <input type="text" value={formData.server} onChange={(e) => handleChange('server', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode) + ' font-mono'} />
                    </Field>
                    
                    <Field label="端口 (port)">
                        <input type="number" value={formData.port} onChange={(e) => handleChange('port', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                    </Field>

                    {/* UUID/Password */}
                    {['vless', 'vmess', 'tuic'].includes(formData.type) && (
                        <Field label="用户 ID (id)">
                            <input type="text" value={formData.uuid} onChange={(e) => handleChange('uuid', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode) + ' font-mono'} />
                        </Field>
                    )}

                    {['socks5', 'http'].includes(formData.type) && (
                        <>
                            <Field label="用户名 (username)">
                                <input type="text" value={formData.username} onChange={(e) => handleChange('username', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode) + ' font-mono'} />
                            </Field>
                            <Field label="密码 (password)">
                                <input type="text" value={formData.password} onChange={(e) => handleChange('password', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode) + ' font-mono'} />
                            </Field>
                        </>
                    )}

                    {['trojan', 'ss', 'hysteria2', 'tuic', 'anytls'].includes(formData.type) && (
                        <Field label="密码 (password)">
                            <input type="text" value={formData.password} onChange={(e) => handleChange('password', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode) + ' font-mono'} />
                        </Field>
                    )}

                    {/* VLESS specific */}
                    {formData.type === 'vless' && (
                        <>
                            <Field label="流控 (flow)">
                                <select value={formData.flow} onChange={(e) => handleChange('flow', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value=""></option>
                                    <option value="xtls-rprx-vision">xtls-rprx-vision</option>
                                    <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
                                </select>
                            </Field>
                            <Field label="加密方式 (encryption)">
                                <input
                                    type="text"
                                    value={formData.encryption}
                                    onChange={(e) => handleChange('encryption', e.target.value)}
                                    disabled={!isCustomNode}
                                    placeholder="none 或其它加密名"
                                    className={inputClass(!isCustomNode)}
                                />
                                <p className="text-xs text-gray-500 mt-1">常见值: none / aes-128-gcm / chacha20-poly1305 / auto</p>
                            </Field>
                        </>
                    )}

                    {/* VMess specific */}
                    {formData.type === 'vmess' && (
                        <>
                            <Field label="额外 ID (alterId)">
                                <input type="number" value={formData.alterId} onChange={(e) => handleChange('alterId', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                            </Field>
                            <Field label="加密方式 (security)">
                                <select value={formData.cipher} onChange={(e) => handleChange('cipher', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value="auto">auto</option>
                                    <option value="aes-128-gcm">aes-128-gcm</option>
                                    <option value="chacha20-poly1305">chacha20-poly1305</option>
                                    <option value="none">none</option>
                                </select>
                            </Field>
                        </>
                    )}

                    {/* SS specific */}
                    {formData.type === 'ss' && (
                        <Field label="加密方式 (method)">
                            <select value={formData.cipher} onChange={(e) => handleChange('cipher', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                <option value="aes-256-gcm">aes-256-gcm</option>
                                <option value="aes-128-gcm">aes-128-gcm</option>
                                <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
                                <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
                                <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
                            </select>
                        </Field>
                    )}

                    {/* Mux */}
                    {['vless', 'vmess', 'trojan'].includes(formData.type) && (
                        <Field label="开启 Mux 多路复用">
                            <label className="flex items-center gap-2 cursor-pointer">
                                <input type="checkbox" checked={formData.muxEnabled} onChange={(e) => handleChange('muxEnabled', e.target.checked)} disabled={!isCustomNode} className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500" />
                            </label>
                        </Field>
                    )}

                    {/* Transport layer */}
                    {getTransportOptions(formData.type).length > 0 && (
                        <>
                            <Divider title="底层传输方式 (transport)" />
                            <Field label="传输协议 (network)">
                                <select value={formData.network} onChange={(e) => handleChange('network', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    {getTransportOptions(formData.type).map(network => (
                                        <option key={network} value={network}>{network}</option>
                                    ))}
                                </select>
                            </Field>
                        </>
                    )}

                    {/* xhttp mode */}
                    {formData.network === 'xhttp' && (
                        <Field label="xhttp Mode">
                            <select value={formData.xhttpMode} onChange={(e) => handleChange('xhttpMode', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                <option value="auto">auto</option>
                                <option value="packet-up">packet-up</option>
                                <option value="stream-up">stream-up</option>
                                <option value="stream-one">stream-one</option>
                            </select>
                        </Field>
                    )}

                    {['ws', 'httpupgrade', 'http', 'h2', 'xhttp'].includes(formData.network) && (
                        <>
                            <Field label="伪装域名 (host)">
                                <input type="text" value={formData.host} onChange={(e) => handleChange('host', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                            </Field>
                            <Field label="路径 (path)">
                                <input type="text" value={formData.path} onChange={(e) => handleChange('path', e.target.value)} disabled={!isCustomNode} placeholder="/" className={inputClass(!isCustomNode)} />
                            </Field>
                        </>
                    )}

                    {/* gRPC serviceName - only for grpc */}
                    {formData.network === 'grpc' && (
                        <Field label="gRPC serviceName">
                            <input type="text" value={formData.grpcServiceName} onChange={(e) => handleChange('grpcServiceName', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                        </Field>
                    )}

                    {/* Transport layer security */}
                    {TLS_PROTOCOLS.has(formData.type) && (
                        <>
                            <Divider title="传输层安全 (TLS)" />
                            <Field label="传输层安全 (TLS)">
                                <select value={formData.security} onChange={(e) => handleChange('security', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value=""></option>
                                    <option value="tls">tls</option>
                                    {REALITY_PROTOCOLS.has(formData.type) && <option value="reality">reality</option>}
                                </select>
                            </Field>
                        </>
                    )}

                    {(formData.security === 'tls' || formData.security === 'reality') && (
                        <>
                            <Field label="SNI">
                                <input type="text" value={formData.sni} onChange={(e) => handleChange('sni', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                            </Field>
                            <Field label="客户端指纹 (uTLS fingerprint)">
                                <select value={formData.clientFingerprint} onChange={(e) => handleChange('clientFingerprint', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value=""></option>
                                    <option value="chrome">chrome</option>
                                    <option value="firefox">firefox</option>
                                    <option value="safari">safari</option>
                                    <option value="ios">ios</option>
                                    <option value="android">android</option>
                                    <option value="edge">edge</option>
                                    <option value="360">360</option>
                                    <option value="qq">qq</option>
                                    <option value="random">random</option>
                                    <option value="randomized">randomized</option>
                                </select>
                            </Field>
                            <Field label="证书指纹 (SHA-256 pin)">
                                <input
                                    type="text"
                                    value={formData.certificateFingerprint}
                                    onChange={(e) => handleChange('certificateFingerprint', e.target.value)}
                                    disabled={!isCustomNode}
                                    placeholder="pinSHA256 / Mihomo fingerprint"
                                    className={inputClass(!isCustomNode) + ' font-mono text-xs'}
                                />
                            </Field>
                        </>
                    )}

                    {(formData.security === 'tls' || formData.security === 'reality') && (
                        <>
                            <Field label="Alpn">
                                <select value={formData.alpn} onChange={(e) => handleChange('alpn', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value=""></option>
                                    <option value="h3">h3</option>
                                    <option value="h2,http/1.1">h2,http/1.1</option>
                                    <option value="h2">h2</option>
                                    <option value="http/1.1">http/1.1</option>
                                    <option value="h3,h2">h3,h2</option>
                                    <option value="h3,h2,http/1.1">h3,h2,http/1.1</option>
                                </select>
                            </Field>
                            {formData.security === 'tls' && (
                                <Field label="跳过证书验证 (allowInsecure)">
                                    <select value={formData.allowInsecure ? 'true' : 'false'} onChange={(e) => handleChange('allowInsecure', e.target.value === 'true')} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                        <option value="false">false</option>
                                        <option value="true">true</option>
                                    </select>
                                </Field>
                            )}
                        </>
                    )}

                    {formData.security === 'reality' && (
                        <>
                            <Field label="PublicKey">
                                <input type="text" value={formData.publicKey} onChange={(e) => handleChange('publicKey', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode) + ' font-mono text-xs'} />
                            </Field>
                            <Field label="ShortId">
                                <input type="text" value={formData.shortId} onChange={(e) => handleChange('shortId', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode) + ' font-mono'} />
                            </Field>
                        </>
                    )}

                    {/* Hysteria2 */}
                    {formData.type === 'hysteria2' && (
                        <>
                            <Divider title="Hysteria2" />
                            <Field label="Obfs">
                                <select value={formData.obfs} onChange={(e) => handleChange('obfs', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value=""></option>
                                    <option value="salamander">salamander</option>
                                </select>
                            </Field>
                            <Field label="Obfs Password">
                                <input type="text" value={formData.obfsPassword} onChange={(e) => handleChange('obfsPassword', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                            </Field>
                        </>
                    )}

                    {/* TUIC */}
                    {formData.type === 'tuic' && (
                        <>
                            <Divider title="TUIC" />
                            <Field label="拥塞控制">
                                <select value={formData.congestionController} onChange={(e) => handleChange('congestionController', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value="bbr">bbr</option>
                                    <option value="cubic">cubic</option>
                                    <option value="new_reno">new_reno</option>
                                </select>
                            </Field>
                            <Field label="UDP 中继模式">
                                <select value={formData.udpRelayMode} onChange={(e) => handleChange('udpRelayMode', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value="native">native</option>
                                    <option value="quic">quic</option>
                                </select>
                            </Field>
                        </>
                    )}

                    {/* Raw JSON */}
                    <Divider title="原始配置" />
                    <pre className="w-full p-3 bg-gray-900 border border-gray-700 rounded text-xs text-gray-400 overflow-x-auto max-h-32">
                        {JSON.stringify(node, null, 2)}
                    </pre>
                </div>

                {/* Footer */}
                <div className="p-4 border-t border-gray-700 flex justify-end flex-shrink-0">
                    <div className="flex gap-3">
                        <button onClick={onClose} className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg">取消</button>
                        {isCustomNode && (
                            <button onClick={handleSave} disabled={saving} className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg flex items-center gap-2 disabled:opacity-50">
                                {saving && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
                                <Save size={16} />
                                确定
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
