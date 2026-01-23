
import React from 'react';
import { RefreshCw, Trash2, Clock, Calendar, Edit2, GripVertical, Copy, FileText } from 'lucide-react';
import { getTrafficInfo, getAvatarTheme, formatDate } from '../utils/format';

export default function SubscriptionCard({
    sub,
    refreshingId,
    draggedItem,
    dragOverItem,
    index,
    onToggle,
    onRefresh,
    onDelete,
    onEdit,
    onSchedule,
    onDragStart,
    onDragOver,
    onDragEnd,
    copyUrl
}) {
    const traffic = getTrafficInfo(sub);
    const isRefreshing = refreshingId === sub.id;
    const isDragging = draggedItem === index;
    const isDragOver = dragOverItem === index;
    const isLocal = sub.type === 'local';

    const theme = getAvatarTheme(sub.name);
    const firstChar = sub.name.charAt(0).toUpperCase();

    return (
        <div
            draggable
            onDragStart={(e) => onDragStart(e, index)}
            onDragOver={(e) => onDragOver(e, index)}
            onDragEnd={onDragEnd}
            className={`group relative bg-gray-800 rounded-xl transition-all duration-300 hover:shadow-xl hover:shadow-black/20 cursor-move border-t-4 ${sub.enabled !== false ? 'border-t-emerald-500' : 'border-t-gray-500'
                } ${isDragging ? 'opacity-50 scale-95' : ''} ${isDragOver ? 'ring-2 ring-blue-500' : ''}`}
        >
            <div className="p-5 space-y-5">
                {/* Header Section */}
                <div className="flex items-start justify-between">
                    <div className="flex items-center gap-4">
                        {/* Avatar */}
                        <div className={`w-12 h-12 rounded-full flex items-center justify-center text-xl font-bold ${theme.bg} ${theme.text}`}>
                            {firstChar}
                        </div>
                        <div>
                            <h3 className="font-bold text-lg text-white mb-1 group-hover:text-blue-400 transition-colors">
                                {sub.name}
                            </h3>
                            <div className="flex items-center gap-2">
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        onToggle(sub.id);
                                    }}
                                    className={`px-2 py-0.5 text-xs rounded font-medium transition-colors ${sub.enabled !== false
                                        ? 'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30'
                                        : 'bg-gray-600/30 text-gray-400 hover:bg-gray-600/50'
                                        }`}
                                >
                                    {sub.enabled !== false ? '启用' : '禁用'}
                                </button>
                            </div>
                        </div>
                    </div>

                    <GripVertical className="text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity cursor-grab active:cursor-grabbing" size={20} />
                </div>

                {/* Tags Row */}
                <div className="flex flex-wrap gap-2">
                    {/* Local indicator */}
                    {isLocal && (
                        <div className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-purple-500/20 text-purple-400 text-xs font-medium">
                            <FileText size={12} />
                            本地导入
                        </div>
                    )}
                    <div className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-blue-500/20 text-blue-400 text-xs font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                        {sub.node_count || 0} 节点
                    </div>
                    {!isLocal && sub.cron_expr && (
                        <div className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-cyan-500/20 text-cyan-400 text-xs font-medium font-mono" title="Cron 表达式">
                            <Clock size={12} />
                            {sub.cron_expr}
                        </div>
                    )}
                </div>

                {/* Time Info */}
                <div className="grid grid-cols-2 gap-4 text-xs">
                    <div>
                        <div className="text-gray-500 mb-1 flex items-center gap-1">
                            <Clock size={12} />
                            {isLocal ? '导入时间' : '上次运行'}
                        </div>
                        <div className="text-gray-300 font-medium">
                            {sub.last_update ? formatDate(sub.last_update).split(' ')[0] : '-'}
                        </div>
                        <div className="text-gray-400 scale-90 origin-top-left">
                            {sub.last_update ? formatDate(sub.last_update).split(' ')[1] : ''}
                        </div>
                    </div>
                    {!isLocal && (
                        <div>
                            <div className="text-gray-500 mb-1 flex items-center gap-1">
                                <Calendar size={12} />
                                下次运行
                            </div>
                            <div className="text-gray-300 font-medium">
                                {sub.next_update || '-'}
                            </div>
                        </div>
                    )}
                </div>

                {/* Settings / Usage Info */}
                <div className="bg-gray-900/50 rounded-lg p-3">
                    <div className="text-xs text-gray-500 mb-2">用量信息</div>
                    {isLocal ? (
                        <div className="text-sm text-gray-500 py-1">
                            本地导入无用量信息
                        </div>
                    ) : traffic ? (
                        <div className="space-y-2">
                            <div className="flex justify-between items-end">
                                <span className={`text-sm font-bold ${parseFloat(traffic.percent) > 90 ? 'text-red-400' :
                                    parseFloat(traffic.percent) > 70 ? 'text-yellow-400' : 'text-emerald-400'
                                    }`}>
                                    {traffic.used}
                                </span>
                                <span className="text-xs text-gray-400 mb-0.5">/ {traffic.total || '∞'}</span>
                            </div>
                            {traffic.total && (
                                <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                                    <div
                                        className={`h-full rounded-full transition-all ${parseFloat(traffic.percent) > 90 ? 'bg-red-500' :
                                            parseFloat(traffic.percent) > 70 ? 'bg-yellow-500' : 'bg-emerald-500'
                                            }`}
                                        style={{ width: `${traffic.percent}%` }}
                                    />
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="text-sm text-gray-500 py-1">
                            未获取到用量
                        </div>
                    )}
                </div>

                {/* Actions Bar */}
                <div className="flex items-center justify-center gap-3 pt-2 border-t border-gray-700/50">
                    {/* Copy URL - Only for URL subscriptions */}
                    {!isLocal && (
                        <button
                            onClick={() => copyUrl(sub.url)}
                            className="w-9 h-9 rounded-full flex items-center justify-center bg-purple-500/10 text-purple-400 hover:bg-purple-500/20 transition-colors"
                            title="复制链接"
                        >
                            <Copy size={16} />
                        </button>
                    )}

                    {/* Refresh - Only for URL subscriptions */}
                    {!isLocal && (
                        <button
                            onClick={() => onRefresh(sub.id)}
                            disabled={isRefreshing}
                            className="w-9 h-9 rounded-full flex items-center justify-center bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
                            title="更新订阅"
                        >
                            <RefreshCw size={16} className={isRefreshing ? 'animate-spin' : ''} />
                        </button>
                    )}

                    {/* Schedule - Only for URL subscriptions */}
                    {!isLocal && (
                        <button
                            onClick={() => onSchedule(sub)}
                            className={`w-9 h-9 rounded-full flex items-center justify-center transition-colors ${sub.cron_expr
                                ? 'bg-blue-500/10 text-blue-400 hover:bg-blue-500/20'
                                : 'bg-gray-600/10 text-gray-400 hover:bg-gray-600/20'
                                }`}
                            title="定时设置"
                        >
                            <Clock size={16} />
                        </button>
                    )}

                    {/* Edit */}
                    <button
                        onClick={() => onEdit(sub)}
                        className="w-9 h-9 rounded-full flex items-center justify-center bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 transition-colors"
                        title="编辑"
                    >
                        <Edit2 size={16} />
                    </button>

                    {/* Delete */}
                    <button
                        onClick={() => onDelete(sub.id)}
                        className="w-9 h-9 rounded-full flex items-center justify-center bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                        title="删除"
                    >
                        <Trash2 size={16} />
                    </button>
                </div>
            </div>
        </div>
    );
}
