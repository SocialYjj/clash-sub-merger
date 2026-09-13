
import { useState, useEffect, useRef } from 'react';
import { X, Copy, Check, FileText } from 'lucide-react';
import request, { isRequestCanceled } from '../utils/request';
import { copyToClipboard } from '../utils/clipboard';

const API_BASE = '/api';

export default function EditSubscriptionModal({ sub, onClose, onRefreshList, showToast }) {
    const [editName, setEditName] = useState('');
    const [editUrl, setEditUrl] = useState('');
    const [editContent, setEditContent] = useState('');
    const [loading, setLoading] = useState(false);
    const [parseResult, setParseResult] = useState(null);
    const previewRequestSeq = useRef(0);
    const dialogRef = useRef(null);

    const isLocal = sub?.type === 'local';

    useEffect(() => {
        const previous = document.activeElement;
        dialogRef.current?.focus();
        const handleKeyDown = (event) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                onClose();
            }
        };
        document.addEventListener('keydown', handleKeyDown);
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
            if (previous && typeof previous.focus === 'function') previous.focus();
        };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- Escape 监听与焦点管理只在挂载时绑定一次；补 onClose 依赖会在父级重渲染时重新捕获焦点
    }, []);

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
            previewRequestSeq.current += 1;
            setParseResult(null);
            return;
        }

        const controller = new AbortController();
        const requestId = ++previewRequestSeq.current;
        const timer = setTimeout(async () => {
            try {
                const res = await request.post(`${API_BASE}/subscriptions/parse-preview`, {
                    name: editName || 'preview',
                    content: editContent
                }, { signal: controller.signal });
                if (!controller.signal.aborted && requestId === previewRequestSeq.current) {
                    setParseResult(res.data);
                }
            } catch (e) {
                if (controller.signal.aborted || isRequestCanceled(e)) return;
                if (requestId === previewRequestSeq.current) {
                    setParseResult({ status: 'error', error: e.message, node_count: 0 });
                }
            }
        }, 500);

        return () => {
            clearTimeout(timer);
            controller.abort();
            previewRequestSeq.current += 1;
        };
    }, [editContent, editName, isLocal]);

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
            onRefreshList?.();
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim/50" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
            <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="edit-subscription-title" tabIndex={-1} className="bg-surface-2 rounded-xl p-6 w-full max-w-lg mx-4 border border-line max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                        <h2 id="edit-subscription-title" className="text-xl font-bold text-ink">编辑订阅</h2>
                        {isLocal && (
                            <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-purple-500/20 text-purple-400">
                                <FileText size={12} />
                                本地导入
                            </span>
                        )}
                    </div>
                    <button onClick={onClose} className="text-ink-2 hover:text-ink">
                        <X size={20} />
                    </button>
                </div>
                <div className="space-y-4">
                    {/* Name input */}
                    <div>
                        <label className="block text-sm text-ink-2 mb-1">订阅名称</label>
                        <input
                            type="text"
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            className="w-full px-3 py-2 bg-surface-3 border border-line-strong rounded-lg text-ink placeholder-ink-3 focus:outline-none focus:border-blue-500"
                        />
                    </div>

                    {/* URL input - Only for URL subscriptions */}
                    {!isLocal && (
                        <div>
                            <label className="block text-sm text-ink-2 mb-1">订阅地址</label>
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    value={editUrl}
                                    onChange={(e) => setEditUrl(e.target.value)}
                                    className="flex-1 px-3 py-2 bg-surface-3 border border-line-strong rounded-lg text-ink placeholder-ink-3 focus:outline-none focus:border-blue-500"
                                />
                                <button
                                    onClick={() => copyUrl(editUrl)}
                                    className="p-2 text-ink-2 hover:text-ink bg-surface-3 rounded-lg"
                                    title="复制"
                                >
                                    <Copy size={18} />
                                </button>
                            </div>
                            <p className="text-xs text-ink-3 mt-1">修改地址后会自动重新获取订阅</p>
                        </div>
                    )}

                    {/* Content input - Only for local subscriptions */}
                    {isLocal && (
                        <>
                            <div>
                                <label className="block text-sm text-ink-2 mb-1">
                                    订阅内容
                                    <span className="text-ink-3 ml-2">(留空则不修改)</span>
                                </label>
                                <textarea
                                    value={editContent}
                                    onChange={(e) => setEditContent(e.target.value)}
                                    placeholder="粘贴新的订阅内容..."
                                    rows={8}
                                    className="w-full px-3 py-2 bg-surface-3 border border-line-strong rounded-lg text-ink placeholder-ink-3 focus:outline-none focus:border-blue-500 font-mono text-sm"
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
                            <div className="text-sm text-ink-2">
                                当前节点数: <span className="text-ink font-medium">{sub?.node_count || 0}</span>
                            </div>
                        </>
                    )}
                </div>
                <div className="flex justify-end gap-2 mt-6">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 text-ink-2 hover:text-ink transition-colors"
                    >
                        取消
                    </button>
                    <button
                        onClick={saveEdit}
                        disabled={!editName.trim() || loading || (isLocal && editContent && parseResult?.status === 'error')}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-ink rounded-lg transition-colors disabled:opacity-50"
                    >
                        {loading ? '保存中...' : '保存'}
                    </button>
                </div>
            </div>
        </div>
    );
}
