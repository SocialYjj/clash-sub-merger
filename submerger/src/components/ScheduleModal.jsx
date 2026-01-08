
import React, { useState, useEffect, useRef } from 'react';
import { X, Clock } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

export default function ScheduleModal({ sub, onClose, onRefresh, showToast }) {
    const [cronValue, setCronValue] = useState('');
    const [nextRun, setNextRun] = useState(null);
    const [error, setError] = useState('');
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        if (sub) {
            setCronValue(sub.cron_expr || '');
            calculateNextRun(sub.cron_expr || '');
        }
    }, [sub]);
    const validateCronDebounced = useRef(null);

    const calculateNextRun = async (cron) => {
        if (!cron || !cron.trim()) {
            setNextRun(null);
            setError('');
            return;
        }

        // Basic format check
        const parts = cron.trim().split(/\s+/);
        if (parts.length !== 5) {
            setError('格式错误：需要5个字段 (分 时 日 月 周)');
            setNextRun(null);
            return;
        }

        // Call backend API for accurate validation
        try {
            const response = await axios.post(`${API_BASE}/scheduler/validate-cron`, {
                cron_expr: cron.trim()
            });

            if (response.data.valid) {
                setNextRun(response.data.next_run);
                setError('');
            } else {
                setError(response.data.error || '无效的 cron 表达式');
                setNextRun(null);
            }
        } catch (e) {
            // Fallback: just clear error if API fails
            setError('');
            setNextRun(null);
        }
    };

    const handleInputChange = (e) => {
        const newValue = e.target.value;
        setCronValue(newValue);

        // Debounce API calls
        if (validateCronDebounced.current) {
            clearTimeout(validateCronDebounced.current);
        }
        validateCronDebounced.current = setTimeout(() => {
            calculateNextRun(newValue);
        }, 300);
    };

    const handleExampleClick = (expr) => {
        setCronValue(expr);
        calculateNextRun(expr);
    };

    const handleClear = () => {
        setCronValue('');
        setNextRun(null);
        setError('');
    };

    const saveSchedule = async () => {
        if (!sub) return;

        setSaving(true);
        try {
            const valueToSave = cronValue.trim() || null;
            console.log('Saving schedule for', sub.id, 'value:', valueToSave);

            const response = await axios.put(`${API_BASE}/subscriptions/${sub.id}/schedule`, {
                cron_expr: valueToSave
            });

            console.log('Save response:', response.data);
            showToast?.(valueToSave ? '定时更新已设置' : '定时更新已清除');
            onClose();
            onRefresh?.(sub.id);
        } catch (err) {
            console.error('Save failed:', err);
            showToast?.('设置失败: ' + (err.response?.data?.detail || err.message), 'error');
        } finally {
            setSaving(false);
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

                <div className="space-y-4">
                    {/* Current status */}
                    <div className="flex items-center gap-2">
                        <Clock size={16} className="text-gray-400" />
                        <span className="text-sm text-gray-300">
                            {cronValue ? `当前设置: ${cronValue}` : '未设置定时更新'}
                        </span>
                    </div>

                    {/* Cron input */}
                    <div>
                        <label className="block text-sm text-gray-400 mb-2">Cron 表达式</label>
                        <input
                            type="text"
                            value={cronValue}
                            onChange={handleInputChange}
                            placeholder="分 时 日 月 周 (例: 0 */6 * * *)"
                            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                    </div>

                    {/* Format hint */}
                    <p className="text-xs text-gray-500">
                        格式: 分钟(0-59) 小时(0-23) 日(1-31) 月(1-12) 周(0=周一...6=周日)
                    </p>

                    {/* Error message */}
                    {error && (
                        <p className="text-xs text-red-400">{error}</p>
                    )}

                    {/* Next run time */}
                    {nextRun && !error && (
                        <div className="text-sm text-green-400 bg-green-500/10 px-3 py-2 rounded-lg">
                            下次执行: {nextRun}
                        </div>
                    )}

                    {/* Common examples */}
                    <div className="text-xs text-gray-500 space-y-1 bg-gray-900/50 p-3 rounded-lg">
                        <div className="font-medium text-gray-400 mb-2">常用示例 (点击填入):</div>
                        <div className="grid grid-cols-2 gap-2">
                            {[
                                { expr: '0 * * * *', label: '每小时' },
                                { expr: '0 */6 * * *', label: '每6小时' },
                                { expr: '0 0 * * *', label: '每天凌晨' },
                                { expr: '0 0 * * 0', label: '每周一' },
                                { expr: '0 0 1 * *', label: '每月1号' },
                                { expr: '0 */12 * * *', label: '每12小时' },
                            ].map(({ expr, label }) => (
                                <button
                                    key={expr}
                                    type="button"
                                    onClick={() => handleExampleClick(expr)}
                                    className="text-left px-2 py-1 hover:bg-gray-700 rounded transition-colors"
                                >
                                    <code className="text-cyan-400">{expr}</code>
                                    <span className="text-gray-500 ml-1">{label}</span>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="flex justify-between mt-6">
                    <button
                        onClick={handleClear}
                        className="px-4 py-2 text-red-400 hover:text-red-300 transition-colors"
                        disabled={!cronValue}
                    >
                        清除
                    </button>
                    <div className="flex gap-2">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                        >
                            取消
                        </button>
                        <button
                            onClick={saveSchedule}
                            disabled={saving || !!error}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
                        >
                            {saving ? '保存中...' : '保存'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
