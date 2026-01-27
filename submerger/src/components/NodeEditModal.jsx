import React, { useState, useEffect } from 'react';
import { X, Save, Server } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

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

            setFormData({
                // Basic
                name: node.name || '',
                type: node.type || 'vless',
                server: node.server || '',
                port: node.port || 443,
                // Auth
                uuid: node.uuid || '',
                password: node.password || '',
                alterId: node.alterId || 0,
                // VLESS specific
                flow: node.flow || '',
                encryption: node.encryption || 'none',
                // Transport
                network: node.network || 'tcp',
                headerType: node['header-type'] || '',
                host: wsOpts.headers?.Host || h2Opts.host || '',
                path: wsOpts.path || h2Opts.path || '',
                grpcServiceName: grpcOpts['grpc-service-name'] || '',
                grpcMode: grpcOpts.mode || 'gun',
                xhttpMode: node['xhttp-mode'] || 'auto',
                // TLS
                security: node['reality-opts'] ? 'reality' : (node.tls ? 'tls' : ''),
                sni: node.sni || node.servername || '',
                fingerprint: node['client-fingerprint'] || '',
                alpn: Array.isArray(node.alpn) ? node.alpn.join(',') : (node.alpn || ''),
                allowInsecure: node['skip-cert-verify'] || false,
                // Reality
                publicKey: realityOpts['public-key'] || '',
                shortId: realityOpts['short-id'] || '',
                spiderX: realityOpts['spider-x'] || '',
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
        setFormData(prev => ({ ...prev, [field]: value }));
    };

    const buildNodeObject = () => {
        const nodeObj = {
            name: formData.name,
            type: formData.type,
            server: formData.server,
            port: parseInt(formData.port) || 443,
        };

        // Auth
        if (['vless', 'vmess', 'tuic'].includes(formData.type)) {
            nodeObj.uuid = formData.uuid;
        }
        if (formData.type === 'vmess') {
            nodeObj.alterId = parseInt(formData.alterId) || 0;
            nodeObj.cipher = formData.cipher || 'auto';
        }
        if (['trojan', 'ss', 'hysteria2', 'tuic'].includes(formData.type)) {
            nodeObj.password = formData.password;
        }
        if (formData.type === 'ss') {
            nodeObj.cipher = formData.cipher;
        }

        // VLESS
        if (formData.type === 'vless') {
            if (formData.flow) nodeObj.flow = formData.flow;
            if (formData.encryption && formData.encryption !== 'none') {
                nodeObj.encryption = formData.encryption;
            }
        }

        // Transport
        if (formData.network && formData.network !== 'tcp') {
            nodeObj.network = formData.network;
        }
        // Header type for tcp, kcp, quic
        if (['tcp', 'kcp', 'quic'].includes(formData.network) && formData.headerType) {
            nodeObj['header-type'] = formData.headerType;
        }
        if (formData.network === 'ws' || formData.network === 'httpupgrade') {
            nodeObj['ws-opts'] = {};
            if (formData.path) nodeObj['ws-opts'].path = formData.path;
            if (formData.host) nodeObj['ws-opts'].headers = { Host: formData.host };
        }
        if (formData.network === 'grpc') {
            nodeObj['grpc-opts'] = {};
            if (formData.grpcServiceName) nodeObj['grpc-opts']['grpc-service-name'] = formData.grpcServiceName;
            if (formData.grpcMode) nodeObj['grpc-opts'].mode = formData.grpcMode;
        }
        if (formData.network === 'h2') {
            nodeObj['h2-opts'] = {};
            if (formData.host) nodeObj['h2-opts'].host = [formData.host];
            if (formData.path) nodeObj['h2-opts'].path = formData.path;
        }
        if (formData.network === 'xhttp') {
            if (formData.xhttpMode) nodeObj['xhttp-mode'] = formData.xhttpMode;
            if (formData.path) nodeObj.path = formData.path;
            if (formData.host) nodeObj.host = formData.host;
        }

        // TLS
        if (formData.security === 'tls') {
            nodeObj.tls = true;
            if (formData.sni) nodeObj.servername = formData.sni;
            if (formData.fingerprint) nodeObj['client-fingerprint'] = formData.fingerprint;
            if (formData.alpn) nodeObj.alpn = formData.alpn.split(',').map(s => s.trim()).filter(Boolean);
            if (formData.allowInsecure) nodeObj['skip-cert-verify'] = true;
        } else if (formData.security === 'reality') {
            nodeObj.tls = true;
            nodeObj['reality-opts'] = {};
            if (formData.publicKey) nodeObj['reality-opts']['public-key'] = formData.publicKey;
            if (formData.shortId) nodeObj['reality-opts']['short-id'] = formData.shortId;
            if (formData.spiderX) nodeObj['reality-opts']['spider-x'] = formData.spiderX;
            if (formData.sni) nodeObj.servername = formData.sni;
            if (formData.fingerprint) nodeObj['client-fingerprint'] = formData.fingerprint;
        }

        // Mux
        if (formData.muxEnabled) {
            nodeObj.smux = { enabled: true };
        }

        // Hysteria2
        if (formData.type === 'hysteria2') {
            if (formData.obfs) nodeObj.obfs = formData.obfs;
            if (formData.obfsPassword) nodeObj['obfs-password'] = formData.obfsPassword;
        }

        // TUIC
        if (formData.type === 'tuic') {
            if (formData.congestionController) nodeObj['congestion-controller'] = formData.congestionController;
            if (formData.udpRelayMode) nodeObj['udp-relay-mode'] = formData.udpRelayMode;
        }

        return nodeObj;
    };

    const handleSave = async () => {
        if (!isCustomNode) {
            showToast?.('订阅节点仅支持查看', 'warning');
            return;
        }
        setSaving(true);
        try {
            await axios.put(`${API_BASE}/custom-nodes/${node.id}/full`, { node: buildNodeObject() });
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

                    {['trojan', 'ss', 'hysteria2', 'tuic'].includes(formData.type) && (
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
                                <select value={formData.encryption} onChange={(e) => handleChange('encryption', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value="none">none</option>
                                </select>
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
                    <Field label="开启 Mux 多路复用">
                        <label className="flex items-center gap-2 cursor-pointer">
                            <input type="checkbox" checked={formData.muxEnabled} onChange={(e) => handleChange('muxEnabled', e.target.checked)} disabled={!isCustomNode} className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500" />
                        </label>
                    </Field>

                    {/* Transport layer */}
                    <Divider title="底层传输方式 (transport)" />
                    
                    <Field label="传输协议 (network)">
                        <select value={formData.network} onChange={(e) => handleChange('network', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                            <option value="tcp">tcp</option>
                            <option value="kcp">kcp</option>
                            <option value="ws">ws</option>
                            <option value="httpupgrade">httpupgrade</option>
                            <option value="xhttp">xhttp</option>
                            <option value="h2">h2</option>
                            <option value="quic">quic</option>
                            <option value="grpc">grpc</option>
                        </select>
                    </Field>

                    {/* Header type for tcp, kcp, quic, ws, httpupgrade, h2 */}
                    {['tcp', 'kcp', 'quic'].includes(formData.network) && (
                        <Field label="伪装类型 (type)">
                            <select value={formData.headerType} onChange={(e) => handleChange('headerType', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                <option value="">none</option>
                                <option value="srtp">srtp</option>
                                <option value="utp">utp</option>
                                <option value="wechat-video">wechat-video</option>
                                <option value="dtls">dtls</option>
                                <option value="wireguard">wireguard</option>
                                <option value="dns">dns</option>
                            </select>
                        </Field>
                    )}

                    {/* Header type for ws, httpupgrade, h2 - only none */}
                    {['ws', 'httpupgrade', 'h2'].includes(formData.network) && (
                        <Field label="伪装类型 (type)">
                            <select value={formData.headerType} onChange={(e) => handleChange('headerType', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                <option value="">none</option>
                            </select>
                        </Field>
                    )}

                    {/* grpc mode */}
                    {formData.network === 'grpc' && (
                        <Field label="gRPC Mode">
                            <select value={formData.grpcMode} onChange={(e) => handleChange('grpcMode', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                <option value="gun">gun</option>
                                <option value="multi">multi</option>
                            </select>
                        </Field>
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

                    {/* Host and path for ALL network types */}
                    <Field label="伪装域名 (host)">
                        <input type="text" value={formData.host} onChange={(e) => handleChange('host', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                    </Field>
                    <Field label="路径 (path)">
                        <input type="text" value={formData.path} onChange={(e) => handleChange('path', e.target.value)} disabled={!isCustomNode} placeholder="/" className={inputClass(!isCustomNode)} />
                    </Field>

                    {/* gRPC serviceName - only for grpc */}
                    {formData.network === 'grpc' && (
                        <Field label="gRPC serviceName">
                            <input type="text" value={formData.grpcServiceName} onChange={(e) => handleChange('grpcServiceName', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                        </Field>
                    )}

                    {/* Transport layer security */}
                    <Divider title="传输层安全 (TLS)" />
                    
                    <Field label="传输层安全 (TLS)">
                        <select value={formData.security} onChange={(e) => handleChange('security', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                            <option value=""></option>
                            <option value="tls">tls</option>
                            <option value="reality">reality</option>
                        </select>
                    </Field>

                    {(formData.security === 'tls' || formData.security === 'reality') && (
                        <>
                            <Field label="SNI">
                                <input type="text" value={formData.sni} onChange={(e) => handleChange('sni', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
                            </Field>
                            <Field label="Fingerprint">
                                <select value={formData.fingerprint} onChange={(e) => handleChange('fingerprint', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
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
                        </>
                    )}

                    {formData.security === 'tls' && (
                        <>
                            <Field label="Alpn">
                                <select value={formData.alpn} onChange={(e) => handleChange('alpn', e.target.value)} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value=""></option>
                                    <option value="h2,http/1.1">h2,http/1.1</option>
                                    <option value="h2">h2</option>
                                    <option value="http/1.1">http/1.1</option>
                                </select>
                            </Field>
                            <Field label="跳过证书验证 (allowInsecure)">
                                <select value={formData.allowInsecure ? 'true' : 'false'} onChange={(e) => handleChange('allowInsecure', e.target.value === 'true')} disabled={!isCustomNode} className={selectClass(!isCustomNode)}>
                                    <option value="false">false</option>
                                    <option value="true">true</option>
                                </select>
                            </Field>
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
                            <Field label="SpiderX">
                                <input type="text" value={formData.spiderX} onChange={(e) => handleChange('spiderX', e.target.value)} disabled={!isCustomNode} className={inputClass(!isCustomNode)} />
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
