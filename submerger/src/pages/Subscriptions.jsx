import React, { useState } from 'react';
import { Plus, RefreshCw, Server } from 'lucide-react';
import request from '../utils/request';
import SubscriptionCard from '../components/SubscriptionCard';
import AddSubscriptionModal from '../components/AddSubscriptionModal';
import EditSubscriptionModal from '../components/EditSubscriptionModal';
import ScheduleModal from '../components/ScheduleModal';

const API_BASE = '/api';

export default function Subscriptions({
  subscriptions,
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
  const [refreshingId, setRefreshingId] = useState(null);

  // Drag and drop state
  const [draggedItem, setDraggedItem] = useState(null);
  const [dragOverItem, setDragOverItem] = useState(null);

  const openScheduleModal = (sub) => {
    setSelectedSub(sub);
    setShowScheduleModal(true);
  };

  const openEditModal = (sub) => {
    setSelectedSub(sub);
    setShowEditModal(true);
  };

  // Single subscription refresh
  const handleRefreshSingle = async (subId) => {
    setRefreshingId(subId);
    try {
      await onRefresh(subId);
    } finally {
      setRefreshingId(null);
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

  const handleDragEnd = async () => {
    if (draggedItem !== null && dragOverItem !== null && draggedItem !== dragOverItem) {
      const newOrder = [...subscriptions];
      const [removed] = newOrder.splice(draggedItem, 1);
      newOrder.splice(dragOverItem, 0, removed);

      // Call reorder API
      try {
        await request.put(`${API_BASE}/subscriptions/reorder`, {
          order: newOrder.map(s => s.id)
        });
        showToast?.('排序已保存');
        // Only refresh the list, don't re-fetch subscription content
        onRefreshList?.();
      } catch (err) {
        showToast?.('排序失败', 'error');
      }
    }
    setDraggedItem(null);
    setDragOverItem(null);
  };

  const copyUrl = (url) => {
    navigator.clipboard.writeText(url);
    showToast?.('订阅地址已复制');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">机场管理</h1>
          <p className="text-gray-400 text-sm mt-1">管理你的订阅源</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={onRefreshAll}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
            全部更新
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
          >
            <Plus size={18} />
            添加订阅
          </button>
        </div>
      </div>

      {/* Subscription Cards */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {subscriptions?.length > 0 ? (
          subscriptions.map((sub, index) => (
            <SubscriptionCard
              key={sub.id}
              sub={sub}
              index={index}
              refreshingId={refreshingId}
              draggedItem={draggedItem}
              dragOverItem={dragOverItem}
              onToggle={onToggle}
              onRefresh={handleRefreshSingle}
              onDelete={onDelete}
              onEdit={openEditModal}
              onSchedule={openScheduleModal}
              onDragStart={handleDragStart}
              onDragOver={handleDragOver}
              onDragEnd={handleDragEnd}
              copyUrl={copyUrl}
            />
          ))
        ) : (
          <div className="col-span-full flex flex-col items-center justify-center py-20 bg-gray-800/30 border border-gray-700 dashed rounded-2xl">
            <div className="w-20 h-20 bg-gray-800 rounded-full flex items-center justify-center mb-6 text-gray-600">
              <Server size={40} />
            </div>
            <h3 className="text-xl font-bold text-white mb-2">还没有添加订阅</h3>
            <p className="text-gray-400 mb-8 max-w-sm text-center">
              添加订阅后，系统会自动解析节点并合并。支持 Clash、V2Ray 等多种格式。
            </p>
            <button
              onClick={() => setShowAddModal(true)}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-medium transition-colors flex items-center gap-2 shadow-lg shadow-blue-600/20"
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
          onRefresh={onRefresh}
          onRefreshList={onRefreshList}
          showToast={showToast}
        />
      )}

      {showScheduleModal && selectedSub && (
        <ScheduleModal
          sub={selectedSub}
          onClose={() => setShowScheduleModal(false)}
          onRefresh={onRefresh}
          showToast={showToast}
        />
      )}
    </div>
  );
}
