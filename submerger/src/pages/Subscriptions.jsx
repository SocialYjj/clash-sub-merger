import { useRef, useState, useMemo } from 'react';
import { Plus, RefreshCw, Server, Search, X, ListFilter } from 'lucide-react';
import request from '../utils/request';
import { copyToClipboard } from '../utils/clipboard';
import SubscriptionCard from '../components/SubscriptionCard';
import { SkeletonHeader, SkeletonCardGrid } from '../components/Skeleton';
import AddSubscriptionModal from '../components/AddSubscriptionModal';
import EditSubscriptionModal from '../components/EditSubscriptionModal';
import ScheduleModal from '../components/ScheduleModal';
import SubscriptionNodesModal from '../components/SubscriptionNodesModal';

const API_BASE = '/api';

export default function Subscriptions({
  subscriptions,
  initialLoading = false,
  onAdd,
  onDelete,
  onRefresh,
  onRefreshAll,
  onRefreshList,
  onToggle,
  loading,
  showToast,
}) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [selectedSub, setSelectedSub] = useState(null);
  const [showEditModal, setShowEditModal] = useState(false);
  const [refreshingIds, setRefreshingIds] = useState(() => new Set());
  const [showSubscriptionNodesModal, setShowSubscriptionNodesModal] = useState(false);
  const [subscriptionNodesModalSub, setSubscriptionNodesModalSub] = useState(null);
  const [subscriptionNodes, setSubscriptionNodes] = useState([]);
  const [subscriptionNodesLoading, setSubscriptionNodesLoading] = useState(false);
  const [subscriptionNodesError, setSubscriptionNodesError] = useState('');
  const subscriptionNodesRequestId = useRef(0);

  // Drag and drop state
  const [draggedItem, setDraggedItem] = useState(null);
  const [dragOverItem, setDragOverItem] = useState(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  // Compute metrics
  const metrics = useMemo(() => {
    if (!Array.isArray(subscriptions)) {
      return { total: 0, active: 0, disabled: 0, error: 0, local: 0, totalNodes: 0 };
    }
    let active = 0;
    let disabled = 0;
    let error = 0;
    let local = 0;
    let totalNodes = 0;

    for (const sub of subscriptions) {
      if (sub.enabled === false) {
        disabled += 1;
      } else {
        active += 1;
      }
      if (sub.last_error && sub.enabled !== false) {
        error += 1;
      }
      if (sub.type === 'local') {
        local += 1;
      }
      totalNodes += sub.node_count || 0;
    }
    return {
      total: subscriptions.length,
      active,
      disabled,
      error,
      local,
      totalNodes,
    };
  }, [subscriptions]);

  const filteredSubscriptions = useMemo(() => {
    if (!Array.isArray(subscriptions)) return [];
    return subscriptions.filter((sub) => {
      if (statusFilter === 'active' && sub.enabled === false) return false;
      if (statusFilter === 'disabled' && sub.enabled !== false) return false;
      if (statusFilter === 'error' && (!sub.last_error || sub.enabled === false)) return false;
      if (statusFilter === 'local' && sub.type !== 'local') return false;

      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        const matchName = (sub.name || '').toLowerCase().includes(q);
        const matchUrl = (sub.url || '').toLowerCase().includes(q);
        return matchName || matchUrl;
      }
      return true;
    });
  }, [subscriptions, statusFilter, searchQuery]);

  const isFiltering = statusFilter !== 'all' || searchQuery.trim() !== '';

  const openScheduleModal = (sub) => {
    setSelectedSub(sub);
    setShowScheduleModal(true);
  };

  const openEditModal = (sub) => {
    setSelectedSub(sub);
    setShowEditModal(true);
  };

  const closeSubscriptionNodesModal = () => {
    subscriptionNodesRequestId.current += 1;
    setShowSubscriptionNodesModal(false);
    setSubscriptionNodesModalSub(null);
    setSubscriptionNodes([]);
    setSubscriptionNodesError('');
    setSubscriptionNodesLoading(false);
  };

  const openSubscriptionNodesModal = async (sub) => {
    const requestId = ++subscriptionNodesRequestId.current;
    setSubscriptionNodesModalSub(sub);
    setShowSubscriptionNodesModal(true);
    setSubscriptionNodes([]);
    setSubscriptionNodesError('');
    setSubscriptionNodesLoading(true);

    try {
      const response = await request.get(`${API_BASE}/subscriptions/${encodeURIComponent(sub.id)}/nodes`);
      if (requestId !== subscriptionNodesRequestId.current) return;
      setSubscriptionNodes(response.data?.nodes || []);
    } catch (err) {
      if (requestId !== subscriptionNodesRequestId.current) return;
      setSubscriptionNodesError(err.response?.data?.detail || err.message || '节点列表加载失败');
    } finally {
      if (requestId === subscriptionNodesRequestId.current) {
        setSubscriptionNodesLoading(false);
      }
    }
  };

  // Single subscription refresh
  const handleRefreshSingle = async (subId) => {
    setRefreshingIds((current) => {
      const next = new Set(current);
      next.add(subId);
      return next;
    });
    try {
      await onRefresh(subId);
    } finally {
      setRefreshingIds((current) => {
        const next = new Set(current);
        next.delete(subId);
        return next;
      });
    }
  };

  // Drag handlers
  const handleDragStart = (e, index) => {
    setDraggedItem(index);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e, index) => {
    e.preventDefault();
    if (draggedItem === null) return;
    setDragOverItem(index);
  };

  const handleDrop = async (e, dropIndex) => {
    e.preventDefault();
    if (draggedItem === null || dropIndex === null || draggedItem === dropIndex) {
      setDraggedItem(null);
      setDragOverItem(null);
      return;
    }

    const newOrder = [...subscriptions];
    const [removed] = newOrder.splice(draggedItem, 1);
    newOrder.splice(dropIndex, 0, removed);
    setDraggedItem(null);
    setDragOverItem(null);

    // Persist only a valid drop. Cancelling a drag or leaving the list must
    // never submit the current order accidentally.
    try {
      await request.put(`${API_BASE}/subscriptions/reorder`, {
        order: newOrder.map(s => s.id)
      });
      showToast?.('排序已保存');
      onRefreshList?.();
    } catch (err) {
      showToast?.('排序失败', 'error');
    }
  };

  const handleDragEnd = () => {
    setDraggedItem(null);
    setDragOverItem(null);
  };

  const copyUrl = async (url) => {
    const copied = await copyToClipboard(url);
    showToast?.(copied ? '订阅地址已复制' : '复制失败', copied ? 'success' : 'error');
  };

  // Initial fetch in flight: show a skeleton instead of an empty grid flash.
  if (initialLoading) {
    return (
      <div className="space-y-6 animate-pulse p-1" aria-busy="true" aria-label="加载中">
        <SkeletonHeader />
        <SkeletonCardGrid count={8} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-ink">机场管理</h1>
          <div className="flex flex-wrap items-center gap-2 mt-1.5">
            <span className="text-xs text-ink-2">
              共 <strong className="text-ink font-semibold">{metrics.total}</strong> 个订阅源
            </span>
            <span className="text-xs text-ink-4">•</span>
            <span className="text-xs text-ink-2">
              <strong className="text-ink font-semibold">{metrics.totalNodes}</strong> 个节点
            </span>
            {metrics.error > 0 && (
              <>
                <span className="text-xs text-ink-4">•</span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
                  {metrics.error} 个源异常
                </span>
              </>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={onRefreshAll}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-surface-3 hover:bg-surface-4 text-ink rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
            全部更新
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-ink rounded-lg transition-colors"
          >
            <Plus size={18} />
            添加订阅
          </button>
        </div>
      </div>

      {/* Filter and Search Toolbar */}
      {subscriptions?.length > 0 && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-surface-2/40 border border-line/40 rounded-2xl p-2.5 backdrop-blur-sm">
          {/* Status Tabs */}
          <div className="flex flex-wrap items-center gap-1">
            {[
              { id: 'all', label: '全部', count: metrics.total },
              { id: 'active', label: '已启用', count: metrics.active },
              { id: 'disabled', label: '已停用', count: metrics.disabled },
              { id: 'error', label: '异常', count: metrics.error, badgeColor: 'text-rose-400' },
              { id: 'local', label: '本地', count: metrics.local },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setStatusFilter(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
                  statusFilter === tab.id
                    ? 'bg-blue-600 text-ink shadow-sm'
                    : 'text-ink-2 hover:text-ink hover:bg-surface-3/50'
                }`}
              >
                <span>{tab.label}</span>
                <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono tabular-nums ${
                  statusFilter === tab.id ? 'bg-white/20 text-ink' : (tab.badgeColor || 'bg-surface-3 text-ink-3')
                }`}>
                  {tab.count}
                </span>
              </button>
            ))}
          </div>

          {/* Search Input */}
          <div className="relative w-full sm:w-64">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="搜索名称或链接..."
              className="w-full pl-8 pr-7 py-1.5 bg-surface-3/40 border border-line-soft rounded-lg text-xs text-ink placeholder-ink-3 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition-all"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-3 hover:text-ink p-0.5 rounded-full"
                title="清空"
              >
                <X size={13} />
              </button>
            )}
          </div>
        </div>
      )}

      {/* Subscription Cards */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {subscriptions?.length > 0 ? (
          filteredSubscriptions.length > 0 ? (
            filteredSubscriptions.map((sub, index) => (
              <SubscriptionCard
                key={sub.id}
                sub={sub}
                index={index}
                refreshingIds={refreshingIds}
                draggedItem={draggedItem}
                dragOverItem={dragOverItem}
                onToggle={onToggle}
                onRefresh={handleRefreshSingle}
                onDelete={onDelete}
                onEdit={openEditModal}
                onSchedule={openScheduleModal}
                onViewNodes={openSubscriptionNodesModal}
                onDragStart={isFiltering ? undefined : handleDragStart}
                onDragOver={isFiltering ? undefined : handleDragOver}
                onDrop={isFiltering ? undefined : handleDrop}
                onDragEnd={isFiltering ? undefined : handleDragEnd}
                copyUrl={copyUrl}
                isDraggable={!isFiltering}
              />
            ))
          ) : (
            <div className="col-span-full flex flex-col items-center justify-center py-16 bg-surface-2/20 border border-line/50 rounded-2xl text-center">
              <ListFilter size={36} className="text-ink-4 mb-3" />
              <h3 className="text-base font-semibold text-ink mb-1">未找到匹配的订阅源</h3>
              <p className="text-xs text-ink-3 mb-4">没有满足当前搜索或状态条件的订阅</p>
              <button
                type="button"
                onClick={() => { setSearchQuery(''); setStatusFilter('all'); }}
                className="px-4 py-1.5 bg-surface-3 hover:bg-surface-4 text-ink text-xs font-medium rounded-lg transition-colors"
              >
                重置筛选条件
              </button>
            </div>
          )
        ) : (
          <div className="col-span-full flex flex-col items-center justify-center py-20 bg-surface-2/30 border border-line dashed rounded-2xl">
            <div className="w-20 h-20 bg-surface-2 rounded-full flex items-center justify-center mb-6 text-ink-4">
              <Server size={40} />
            </div>
            <h3 className="text-xl font-bold text-ink mb-2">还没有添加订阅</h3>
            <p className="text-ink-2 mb-8 max-w-sm text-center">
              添加订阅后，系统会自动解析节点并合并。支持 Clash、V2Ray 等多种格式。
            </p>
            <button
              onClick={() => setShowAddModal(true)}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-ink rounded-xl font-medium transition-colors flex items-center gap-2 shadow-lg shadow-blue-600/20"
            >
              <Plus size={20} />
              添加第一个订阅
            </button>
          </div>
        )}
      </div>

      {/* Modals */}
      {showAddModal && (
        <AddSubscriptionModal
          onClose={() => setShowAddModal(false)}
          onAdd={onAdd}
          onRefreshList={onRefreshList}
          showToast={showToast}
        />
      )}

      {showEditModal && selectedSub && (
        <EditSubscriptionModal
          sub={selectedSub}
          onClose={() => setShowEditModal(false)}
          onRefreshList={onRefreshList}
          showToast={showToast}
        />
      )}

      {showScheduleModal && selectedSub && (
        <ScheduleModal
          sub={selectedSub}
          onClose={() => setShowScheduleModal(false)}
          onRefreshList={onRefreshList}
          showToast={showToast}
        />
      )}

      {showSubscriptionNodesModal && subscriptionNodesModalSub && (
        <SubscriptionNodesModal
          subscription={subscriptionNodesModalSub}
          nodes={subscriptionNodes}
          loading={subscriptionNodesLoading}
          error={subscriptionNodesError}
          onClose={closeSubscriptionNodesModal}
        />
      )}
    </div>
  );
}
