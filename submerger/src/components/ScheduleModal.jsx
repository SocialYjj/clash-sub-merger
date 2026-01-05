
import React, { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import CronEditor from './CronEditor';
import axios from 'axios';

const API_BASE = '/api';

export default function ScheduleModal({ sub, onClose, onRefresh, showToast }) {
    const [cronValue, setCronValue] = useState('');

    useEffect(() => {
        if (sub) {
            setCronValue(sub.cron_expr || '');
        }
    }, [sub]);

    const saveSchedule = async () => {
        if (!sub) return;
        try {
            await axios.put(`${API_BASE}/subscriptions/${sub.id}/schedule`, {
                cron_expr: cronValue || null
            });
            showToast?.('定时更新已设置');
            onClose();
            onRefresh?.(sub.id);
        } catch (err) {
            showToast?.('设置失败: ' + (err.response?.data?.detail || err.message), 'error');
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md mx-4 border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                    <h2 className="text-xl font-bold text-white">定时更新设置</h2>
                    <button onClick={onClose} className="text-gray-400 hover:text-white">
                        <X size={20} />
                    </button>
                </div>
                <p className="text-gray-400 text-sm mb-4">{sub.name}</p>

                <CronEditor
                    value={cronValue}
                    onChange={setCronValue}
                />

                <div className="flex justify-end gap-2 mt-6">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                    >
                        取消
                    </button>
                    <button
                        onClick={saveSchedule}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
                    >
                        保存
                    </button>
                </div>
            </div>
        </div>
    );
}
