
import React, { useState, useEffect } from 'react';
import { X, Copy } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

export default function EditSubscriptionModal({ sub, onClose, onRefresh, showToast }) {
    const [editName, setEditName] = useState('');
    const [editUrl, setEditUrl] = useState('');

    useEffect(() => {
        if (sub) {
            setEditName(sub.name);
            setEditUrl(sub.url);
        }
    }, [sub]);

    const saveEdit = async () => {
        if (!sub || !editName.trim()) return;
        try {
            await axios.put(`${API_BASE}/subscriptions/${sub.id}`, {
                name: editName.trim(),
                url: editUrl.trim() !== sub.url ? editUrl.trim() : undefined
            });
            showToast?.('订阅已更新');
            onClose();
            onRefresh?.(sub.id);
        } catch (err) {
            showToast?.('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
        }
    };

    const copyUrl = (url) => {
        navigator.clipboard.writeText(url);
        showToast?.('订阅地址已复制');
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md mx-4 border border-gray-700">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-xl font-bold text-white">编辑订阅</h2>
                    <button onClick={onClose} className="text-gray-400 hover:text-white">
                        <X size={20} />
                    </button>
                </div>
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm text-gray-400 mb-1">订阅名称</label>
                        <input
                            type="text"
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                    </div>
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
                        disabled={!editName.trim()}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
                    >
                        保存
                    </button>
                </div>
            </div>
        </div>
    );
}
