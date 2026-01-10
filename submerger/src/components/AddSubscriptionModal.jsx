
import React, { useState, useEffect } from 'react';
import { X, Link, FileText, Check } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

export default function AddSubscriptionModal({ onClose, onAdd, onRefreshList, showToast }) {
    const [type, setType] = useState('url'); // 'url' or 'local'
    const [name, setName] = useState('');
    const [url, setUrl] = useState('');
    const [content, setContent] = useState('');
    const [loading, setLoading] = useState(false);
    const [parseResult, setParseResult] = useState(null);

    // Preview parsing when content changes (debounced)
    useEffect(() => {
        if (type !== 'local' || !content.trim()) {
            setParseResult(null);
            return;
        }

        const timer = setTimeout(async () => {
            try {
                const res = await axios.post(`${API_BASE}/subscriptions/parse-preview`, {
                    name: name || 'preview',
                    content: content
                });
                setParseResult(res.data);
            } catch (e) {
                setParseResult({ status: 'error', error: e.message, node_count: 0 });
            }
        }, 500);

        return () => clearTimeout(timer);
    }, [content, type]);

    const handleAdd = async () => {
        if (!name.trim()) return;
        
        setLoading(true);
        try {
            if (type === 'url') {
                if (!url.trim()) return;
                await onAdd(name.trim(), url.trim());
            } else {
                if (!content.trim()) return;
                await axios.post(`${API_BASE}/subscriptions/local`, {
                    name: name.trim(),
                    content: content.trim()
                });
                showToast?.('本地订阅添加成功');
                onRefreshList?.();
            }
            onClose();
        } catch (e) {
            showToast?.('添加失败: ' + (e.response?.data?.detail || e.message), 'error');
        } finally {
            setLoading(false);
        }
    };

    const isValid = name.trim() && (
        (type === 'url' && url.trim()) ||
        (type === 'local' && content.trim() && parseResult?.status === 'success')
    );

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="bg-gray-800 rounded-xl p-6 w-full max-w-lg mx-4 border border-gray-700 max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-xl font-bold text-white">添加订阅</h2>
                    <button onClick={onClose} className="text-gray-400 hover:text-white">
                        <X size={20} />
                    </button>
                </div>

                {/* Type selector */}
                <div className="flex gap-2 mb-4">
                    <button
                        onClick={() => setType('url')}
                        className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                            type === 'url'
                                ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                                : 'bg-gray-700/50 border-gray-600 text-gray-400 hover:border-gray-500'
                        }`}
                    >
                        <Link size={18} />
                        URL 订阅
                    </button>
                    <button
                        onClick={() => setType('local')}
                        className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-all ${
                            type === 'local'
                                ? 'bg-purple-600/20 border-purple-500 text-purple-400'
                                : 'bg-gray-700/50 border-gray-600 text-gray-400 hover:border-gray-500'
                        }`}
                    >
                        <FileText size={18} />
                        本地导入
                    </button>
                </div>

                <div className="space-y-4">
                    {/* Name input */}
                    <div>
                        <label className="block text-sm text-gray-400 mb-1">订阅名称</label>
                        <input
                            type="text"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            placeholder="例如：我的机场"
                            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                    </div>

                    {/* URL input (for URL type) */}
                    {type === 'url' && (
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">订阅地址</label>
                            <input
                                type="text"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="https://..."
                                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                            />
                        </div>
                    )}

                    {/* Content input (for local type) */}
                    {type === 'local' && (
                        <>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">
                                    订阅内容
                                    <span className="text-gray-500 ml-2">(自动识别 YAML / Base64 / 节点链接)</span>
                                </label>
                                <textarea
                                    value={content}
                                    onChange={(e) => setContent(e.target.value)}
                                    placeholder="粘贴订阅内容..."
                                    rows={8}
                                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
                                />
                            </div>

                            {/* Parse result */}
                            {parseResult && (
                                <div className={`px-3 py-2 rounded-lg text-sm ${
                                    parseResult.status === 'success'
                                        ? 'bg-green-500/10 text-green-400'
                                        : 'bg-red-500/10 text-red-400'
                                }`}>
                                    {parseResult.status === 'success' ? (
                                        <div className="flex items-center gap-2">
                                            <Check size={16} />
                                            <span>识别出 {parseResult.node_count} 个节点</span>
                                        </div>
                                    ) : (
                                        <span>{parseResult.error}</span>
                                    )}
                                </div>
                            )}
                        </>
                    )}
                </div>

                <div className="flex justify-end gap-2 mt-6">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                    >
                        取消
                    </button>
                    <button
                        onClick={handleAdd}
                        disabled={!isValid || loading}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
                    >
                        {loading ? '添加中...' : '添加'}
                    </button>
                </div>
            </div>
        </div>
    );
}
