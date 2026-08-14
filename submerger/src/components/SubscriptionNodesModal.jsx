import React, { useEffect, useRef } from 'react';
import { FileText, Loader2, Server, X } from 'lucide-react';

const getNodeDisplayName = (node) => node?.display_name || node?.name || '未命名节点';

export default function SubscriptionNodesModal({
    subscription,
    nodes,
    loading,
    error,
    onClose,
}) {
    const dialogRef = useRef(null);

    useEffect(() => {
        if (!subscription) return undefined;

        const previouslyFocused = document.activeElement;
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
            if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
                previouslyFocused.focus();
            }
        };
    }, [subscription, onClose]);

    if (!subscription) return null;

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
            onMouseDown={(event) => event.target === event.currentTarget && onClose()}
        >
            <div
                ref={dialogRef}
                role="dialog"
                aria-modal="true"
                aria-labelledby="subscription-nodes-modal-title"
                tabIndex={-1}
                className="flex max-h-[88vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-gray-700 bg-gray-800"
            >
                <div className="flex items-center justify-between border-b border-gray-700 px-5 py-4">
                    <div className="flex min-w-0 items-center gap-3">
                        <div className="rounded-lg bg-blue-500/20 p-2 text-blue-400">
                            {subscription.type === 'local' ? <FileText size={20} /> : <Server size={20} />}
                        </div>
                        <div className="min-w-0">
                            <h2 id="subscription-nodes-modal-title" className="truncate text-lg font-bold text-white">
                                {subscription.name} · 节点列表
                            </h2>
                            <p className="text-xs text-gray-400">
                                共 {loading ? '...' : nodes.length} 个节点
                            </p>
                        </div>
                    </div>
                    <button onClick={onClose} className="shrink-0 text-gray-400 transition-colors hover:text-white" title="关闭">
                        <X size={22} />
                    </button>
                </div>

                <div className="min-h-0 flex-1 overflow-y-auto p-4">
                    {loading ? (
                        <div className="flex min-h-40 items-center justify-center gap-2 text-gray-400">
                            <Loader2 size={20} className="animate-spin" />
                            正在加载节点列表...
                        </div>
                    ) : error ? (
                        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                            {error}
                        </div>
                    ) : nodes.length === 0 ? (
                        <div className="flex min-h-40 items-center justify-center text-sm text-gray-500">
                            当前订阅没有可展示的节点
                        </div>
                    ) : (
                        <div className="overflow-x-auto rounded-lg border border-gray-700">
                            <div className="w-full min-w-[520px]">
                                <div className="grid grid-cols-[52px_minmax(0,1fr)_120px] gap-3 border-b border-gray-700 bg-gray-900/60 px-3 py-2 text-xs text-gray-400">
                                    <span>#</span>
                                    <span>节点名称</span>
                                    <span>协议</span>
                                </div>
                                {nodes.map((node, index) => {
                                    return (
                                        <div
                                            key={node?.id || `${node?.index ?? index}-${getNodeDisplayName(node)}`}
                                            className="grid grid-cols-[52px_minmax(0,1fr)_120px] items-center gap-3 border-b border-gray-700/70 px-3 py-2 text-sm last:border-b-0 hover:bg-gray-700/30"
                                        >
                                            <span className="font-mono text-xs text-gray-500">{index + 1}</span>
                                            <span className="truncate text-white" title={getNodeDisplayName(node)}>{getNodeDisplayName(node)}</span>
                                            <span className="whitespace-nowrap text-blue-300">{node?.type?.toUpperCase() || '-'}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}
                </div>

                <div className="flex justify-end border-t border-gray-700 px-5 py-3">
                    <button onClick={onClose} className="rounded-lg bg-gray-700 px-4 py-2 text-sm text-white transition-colors hover:bg-gray-600">
                        关闭
                    </button>
                </div>
            </div>
        </div>
    );
}
