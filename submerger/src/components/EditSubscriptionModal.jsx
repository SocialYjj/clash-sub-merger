
import React, { useState, useEffect } from 'react';
import { X, Copy, Check, FileText } from 'lucide-react';
import request from '../utils/request';
import { copyToClipboard } from '../utils/clipboard';

const API_BASE = '/api';

export default function EditSubscriptionModal({ sub, onClose, onRefresh, onRefreshList, showToast }) {
    const [editName, setEditName] = useState('');
    const [editUrl, setEditUrl] = useState('');
    const [editContent, setEditContent] = useState('');
    const [loading, setLoading] = useState(false);
    const [parseResult, setParseResult] = useState(null);

    const isLocal = sub?.type === 'local';

    useEffect(() => {
        if (sub) {
            setEditName(sub.name);
            setEditUrl(sub.url || '');
            setEditContent('');
            setParseResult(null);
        }
    }, [sub]);

    // Preview parsing for local subscriptions
    useEffect(() => {
        if (!isLocal || !editContent.trim()) {
            setParseResult(null);
            return;
        }

        const timer = setTimeout(async () => {
            try {
                const res = await request.post(`${API_BASE}/subscriptions/parse-preview`, {
                    name: editName || 'preview',
                    content: editContent
                });
                setParseResult(res.data);
            } catch (e) {
                setParseResult({ status: 'error', error: e.message, node_count: 0 });
            }
        }, 500);

        return () => clearTimeout(timer);
    }, [editContent, isLocal]);

    const saveEdit = async () => {
        if (!sub || !editName.trim()) return;

        setLoading(true);
        try {
            if (isLocal) {
                // Update local subscription
                await request.put(`${API_BASE}/subscriptions/${sub.id}/local`, {
                    name: editName.trim(),
                    content: editContent.trim() || undefined
                });
            } else {
                // Update URL subscription
                await request.put(`${API_BASE}/subscriptions/${sub.id}`, {
                    name: editName.trim(),
                    url: editUrl.trim() !== sub.url ? editUrl.trim() : undefined
                });
            }
            showToast?.('订阅已更新');
            onClose();
            // For local subscriptions, just refresh the list without calling refresh API
            // For URL subscriptions, call refresh API to update content
            if (isLocal) {
                // Just refresh the list to show updated last_update time
                if (onRefreshList) {
                    onRefreshList();
                }
            } else {
                // Refresh URL subscription content
                if (onRefresh) {
                    onRefresh(sub.id);
                }
            }
        } catch (err) {
            showToast?.('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
        } finally {
            setLoading(false);
        }
    };

    const copyUrl = async (url) => {
        const copied = await copyToClipboard(url);
        showToast?.(copied ? '订阅地址已复制' : '复制失败', copied ? 'success' : 'error');
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="bg-gray-800 rounded-xl p-6 w-full max-w-lg mx-4 border border-gray-700 max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                        <h2 className="text-xl font-bold text-white">编辑订阅</h2>
                        {isLocal && (
                            <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-purple-500/20 text-purple-400">
                                <FileText size={12} />
                                本地导入
                            </span>
                        )}
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white">
                        <X size={20} />
                    </button>
                </div>
                <div className="space-y-4">
                    {/* Name input */}
                    <div>
                        <label className="block text-sm text-gray-400 mb-1">订阅名称</label>
                        <input
                            type="text"
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                    </div>

                    {/* URL input - Only for URL subscriptions */}
                    {!isLocal && (
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">订阅地址</label>
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    value={editUrl}
                                    onChange={(e) => setEditUrl(e.target.value)}
                                    className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                                />
                                <button
                                    onClick={() => copyUrl(editUrl)}
                                    className="p-2 text-gray-400 hover:text-white bg-gray-700 rounded-lg"
                                    title="复制"
                                >
                                    <Copy size={18} />
                                </button>
                            </div>
                            <p className="text-xs text-gray-500 mt-1">修改地址后会自动重新获取订阅</p>
                        </div>
                    )}

                    {/* Content input - Only for local subscriptions */}
                    {isLocal && (
                        <>
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">
                                    订阅内容
                                    <span className="text-gray-500 ml-2">(留空则不修改)</span>
                                </label>
                                <textarea
                                    value={editContent}
                                    onChange={(e) => setEditContent(e.target.value)}
                                    placeholder="粘贴新的订阅内容..."
                                    rows={8}
                                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
                                />
                            </div>

                            {/* Parse result */}
                            {parseResult && (
                                <div className={`px-3 py-2 rounded-lg text-sm ${parseResult.status === 'success'
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

                            {/* Current node count */}
                            <div className="text-sm text-gray-400">
                                当前节点数: <span className="text-white font-medium">{sub?.node_count || 0}</span>
                            </div>
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
                        onClick={saveEdit}
                        disabled={!editName.trim() || loading || (isLocal && editContent && parseResult?.status === 'error')}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
                    >
                        {loading ? '保存中...' : '保存'}
                    </button>
                </div>
            </div>
        </div>
    );
}
