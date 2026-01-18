import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Users as UsersIcon, Plus, Trash2, Copy, Key, ToggleLeft, ToggleRight, Edit2, Calendar, Clock, X, ChevronDown, ChevronRight, Check, RefreshCw, Shuffle, Settings, FileCode, Sliders } from 'lucide-react';
import UserConfigEditor from '../components/UserConfigEditor';

const API_BASE = '/api';

// User Settings Modal - for editing template and other settings
const UserSettingsModal = ({ user, onClose, showToast, onSuccess }) => {
  const [templates, setTemplates] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState(user.template_id || 'builtin');
  const [subName, setSubName] = useState(user.sub_name || '');
  const [subFilename, setSubFilename] = useState(user.sub_filename || '');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchTemplates();
  }, []);

  const fetchTemplates = async () => {
    try {
      const res = await axios.get(`${API_BASE}/templates`);
      setTemplates(res.data.templates || []);
    } catch (err) {
      console.error('Failed to fetch templates', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await axios.put(`${API_BASE}/users/${user.id}`, {
        template_id: selectedTemplate,
        sub_name: subName.trim() || '',
        sub_filename: subFilename.trim() || ''
      });
      showToast?.('用户设置已保存');
      onSuccess?.();
      onClose();
    } catch (err) {
      showToast?.('保存失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Settings className="text-purple-400" size={20} />
            用户设置
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X size={20} />
          </button>
        </div>

        <p className="text-sm text-gray-400 mb-4">
          用户: <span className="text-white font-medium">{user.name}</span>
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2 flex items-center gap-2">
              <FileCode size={14} />
              配置模版
            </label>
            {loading ? (
              <div className="text-gray-500 text-sm">加载中...</div>
            ) : (
              <select
                value={selectedTemplate}
                onChange={(e) => setSelectedTemplate(e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
              >
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} {t.is_builtin ? '(内置)' : ''}
                  </option>
                ))}
              </select>
            )}
            <p className="text-xs text-gray-500 mt-1">选择该用户使用的配置模版</p>
          </div>

          <div className="border-t border-gray-700 pt-4">
            <p className="text-xs text-gray-500 mb-3">订阅设置（留空使用全局设置）</p>
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">配置名称</label>
                <input
                  type="text"
                  value={subName}
                  onChange={(e) => setSubName(e.target.value)}
                  placeholder="客户端显示的配置名称"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">订阅文件名</label>
                <input
                  type="text"
                  value={subFilename}
                  onChange={(e) => setSubFilename(e.target.value)}
                  placeholder="下载时的文件名"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
          >
            取消
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {saving && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
            保存
          </button>
        </div>
      </div>
    </div>
  );
};

// Token Modal Component
const TokenModal = ({ user, onClose, showToast, onSuccess }) => {
  const [mode, setMode] = useState('random'); // 'random' or 'custom'
  const [customToken, setCustomToken] = useState('');
  const [saving, setSaving] = useState(false);

  const generateRandomToken = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 32; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setCustomToken(token);
  };

  const handleSave = async () => {
    if (mode === 'custom' && customToken.trim().length < 8) {
      showToast('Token 长度至少需要 8 个字符', 'error');
      return;
    }

    setSaving(true);
    try {
      const payload = mode === 'custom' ? { custom_token: customToken.trim() } : {};
      await axios.post(`${API_BASE}/users/${user.id}/regenerate-token`, payload);
      showToast('Token 已更新', 'success');
      onSuccess();
      onClose();
    } catch (err) {
      showToast('更新失败', 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Key className="text-blue-400" size={20} />
            重新生成 Token
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X size={20} />
          </button>
        </div>

        <p className="text-sm text-gray-400 mb-4">
          用户: <span className="text-white font-medium">{user.name}</span>
        </p>

        {/* Mode Selection */}
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => setMode('random')}
            className={`flex-1 py-2 px-4 rounded-lg text-sm font-medium transition-colors ${mode === 'random'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
              }`}
          >
            <Shuffle size={16} className="inline mr-2" />
            随机生成
          </button>
          <button
            onClick={() => setMode('custom')}
            className={`flex-1 py-2 px-4 rounded-lg text-sm font-medium transition-colors ${mode === 'custom'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
              }`}
          >
            <Key size={16} className="inline mr-2" />
            自定义
          </button>
        </div>

        {/* Custom Token Input */}
        {mode === 'custom' && (
          <div className="mb-6">
            <label className="block text-sm text-gray-400 mb-2">自定义 Token（至少 8 个字符）</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customToken}
                onChange={(e) => setCustomToken(e.target.value)}
                placeholder="输入自定义 Token"
                className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
              />
              <button
                onClick={generateRandomToken}
                className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-400 hover:text-white rounded-lg transition-colors"
                title="生成随机 Token"
              >
                <RefreshCw size={18} />
              </button>
            </div>
            {customToken && customToken.length < 8 && (
              <p className="text-xs text-red-400 mt-1">Token 长度至少需要 8 个字符</p>
            )}
          </div>
        )}

        {mode === 'random' && (
          <div className="mb-6 p-4 bg-gray-700/50 rounded-lg border border-gray-600">
            <p className="text-sm text-gray-300">
              将为用户生成一个新的随机 Token，旧的订阅地址将失效。
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
          >
            取消
          </button>
          <button
            onClick={handleSave}
            disabled={saving || (mode === 'custom' && customToken.trim().length < 8)}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {saving && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
            确认更新
          </button>
        </div>
      </div>
    </div>
  );
};

const AllocationModal = ({ user, onClose, showToast }) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [sources, setSources] = useState({});
  const [allocations, setAllocations] = useState({});
  const [expandedSubs, setExpandedSubs] = useState({});

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [nodesRes, allocRes] = await Promise.all([
        axios.get(`${API_BASE}/available-nodes`),
        axios.get(`${API_BASE}/users/${user.id}/allocations`)
      ]);
      setSources(nodesRes.data.sources);
      setAllocations(allocRes.data.allocations || {});
      setLoading(false);
    } catch (err) {
      showToast('加载数据失败', 'error');
      onClose();
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await axios.put(`${API_BASE}/users/${user.id}/allocations`, {
        subscriptions: allocations
      });
      showToast('分配已保存', 'success');
      onClose();
    } catch (err) {
      showToast('保存失败', 'error');
    } finally {
      setSaving(false);
    }
  };

  const toggleSubscription = (subId, allNodes) => {
    setAllocations(prev => {
      const current = prev[subId];
      if (current && current.includes('*')) {
        // Unselect all
        const next = { ...prev };
        delete next[subId];
        return next;
      } else {
        // Select all
        return { ...prev, [subId]: ['*'] };
      }
    });
  };

  const toggleNode = (subId, nodeName, allNodes) => {
    setAllocations(prev => {
      const current = prev[subId] || [];
      let nextList;

      if (current.includes('*')) {
        // If currently all selected, unselecting one means we need to explicitly list the others
        nextList = allNodes.filter(n => n !== nodeName);
      } else if (current.includes(nodeName)) {
        // Unselect specific
        nextList = current.filter(n => n !== nodeName);
      } else {
        // Select specific
        nextList = [...current, nodeName];
        // Check if we selected all
        if (nextList.length === allNodes.length) {
          nextList = ['*'];
        }
      }

      const next = { ...prev };
      if (nextList.length === 0) {
        delete next[subId];
      } else {
        next[subId] = nextList;
      }
      return next;
    });
  };

  const toggleExpand = (subId) => {
    setExpandedSubs(prev => ({ ...prev, [subId]: !prev[subId] }));
  };

  const isSubSelected = (subId) => {
    return allocations[subId] && allocations[subId].includes('*');
  };

  const isSubPartial = (subId, allNodes) => {
    const current = allocations[subId];
    return current && !current.includes('*') && current.length > 0;
  };

  const isNodeSelected = (subId, nodeName) => {
    const current = allocations[subId];
    if (!current) return false;
    if (current.includes('*')) return true;
    return current.includes(nodeName);
  };

  if (loading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
        <div className="bg-gray-800 rounded-xl p-8 text-center">
          <div className="animate-spin text-blue-500 mb-2">
            <Check size={24} />
          </div>
          <div className="text-gray-400">加载中...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="bg-gray-800 rounded-xl w-full max-w-2xl flex flex-col max-h-[90vh]">
        <div className="p-6 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-white">编辑节点分配</h2>
            <p className="text-gray-400 text-sm mt-1">用户: {user.name}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X size={24} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {Object.entries(sources).map(([subId, data]) => (
            <div key={subId} className="bg-gray-700/30 rounded-lg border border-gray-700 overflow-hidden">
              <div className="flex items-center p-3 bg-gray-700/50 hover:bg-gray-700 transition-colors">
                <button
                  onClick={() => toggleExpand(subId)}
                  className="p-1 mr-2 text-gray-400 hover:text-white"
                >
                  {expandedSubs[subId] ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                </button>

                <div
                  className="flex-1 flex items-center cursor-pointer"
                  onClick={() => toggleSubscription(subId, data.nodes)}
                >
                  <div className={`w-5 h-5 rounded border mr-3 flex items-center justify-center transition-colors ${isSubSelected(subId)
                    ? 'bg-blue-600 border-blue-600 text-white'
                    : isSubPartial(subId, data.nodes)
                      ? 'bg-blue-600/50 border-blue-600 text-white'
                      : 'border-gray-500'
                    }`}>
                    {isSubSelected(subId) && <Check size={14} />}
                    {isSubPartial(subId, data.nodes) && <div className="w-2 h-2 bg-white rounded-full" />}
                  </div>
                  <div>
                    <h3 className="text-white font-medium">{data.name}</h3>
                    <p className="text-xs text-gray-400">{data.nodes.length} 个节点</p>
                  </div>
                </div>
              </div>

              {expandedSubs[subId] && (
                <div className="p-3 grid grid-cols-1 sm:grid-cols-2 gap-2 bg-gray-800/50">
                  {data.nodes.map(nodeName => (
                    <div
                      key={nodeName}
                      className="flex items-center p-2 rounded hover:bg-gray-700/50 cursor-pointer"
                      onClick={() => toggleNode(subId, nodeName, data.nodes)}
                    >
                      <div className={`w-4 h-4 rounded border mr-2 flex items-center justify-center transition-colors ${isNodeSelected(subId, nodeName)
                        ? 'bg-blue-600 border-blue-600 text-white'
                        : 'border-gray-500'
                        }`}>
                        {isNodeSelected(subId, nodeName) && <Check size={12} />}
                      </div>
                      <span className="text-sm text-gray-300 truncate" title={nodeName}>
                        {nodeName}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          {Object.keys(sources).length === 0 && (
            <div className="text-center text-gray-500 py-8">
              暂无可分配的节点或订阅
            </div>
          )}
        </div>

        <div className="p-6 border-t border-gray-700 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
          >
            取消
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors flex items-center gap-2"
          >
            {saving && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
            保存配置
          </button>
        </div>
      </div>
    </div>
  );
};

export default function Users({
  users,
  onAdd,
  onDelete,
  onToggle,
  onCopyUrl,
  onRefreshUsers,
  showToast,
  loading
}) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [tokenUser, setTokenUser] = useState(null);
  const [settingsUser, setSettingsUser] = useState(null);  // For user settings modal
  const [configUser, setConfigUser] = useState(null);  // For visual config editor
  const [newName, setNewName] = useState('');
  const [newExpire, setNewExpire] = useState('');
  const [templates, setTemplates] = useState([]);

  // Load templates on mount
  useEffect(() => {
    fetchTemplates();
  }, []);

  const fetchTemplates = async () => {
    try {
      const res = await axios.get(`${API_BASE}/templates`);
      setTemplates(res.data.templates || []);
    } catch (err) {
      console.error('Failed to fetch templates', err);
    }
  };

  // Helper function to get template name by ID
  const getTemplateName = (templateId) => {
    if (!templateId || templateId === 'builtin') {
      return '内置模版';
    }
    const template = templates.find(t => t.id === templateId);
    return template ? template.name : templateId;
  };

  const handleAdd = async () => {
    if (!newName.trim()) return;
    const expireTime = newExpire ? Math.floor(new Date(newExpire).getTime() / 1000) : 0;
    await onAdd(newName.trim(), expireTime);
    setNewName('');
    setNewExpire('');
    setShowAddModal(false);
  };

  const formatExpire = (timestamp) => {
    if (!timestamp || timestamp === 0) return '永不过期';
    const date = new Date(timestamp * 1000);
    const now = new Date();
    if (date < now) return '已过期';
    return date.toLocaleDateString('zh-CN');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">用户管理</h1>
          <p className="text-gray-400 text-sm mt-1">管理订阅用户和节点分配</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
        >
          <Plus size={18} />
          添加用户
        </button>
      </div>

      {/* Users Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4">
        {users?.length > 0 ? (
          users.map((user) => (
            <div
              key={user.id}
              className="bg-white/5 border border-gray-700/50 rounded-2xl overflow-hidden hover:border-blue-500/30 transition-all hover:shadow-lg hover:shadow-blue-500/5"
            >
              {/* Header */}
              <div className="p-4 border-b border-gray-700/30">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-lg font-bold ${user.enabled !== false
                    ? 'bg-gradient-to-br from-green-400 to-emerald-500 text-white'
                    : 'bg-gray-600 text-gray-400'
                    }`}>
                    {user.name.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="font-semibold text-white truncate">{user.name}</h3>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${user.enabled !== false
                      ? 'bg-green-500/20 text-green-400'
                      : 'bg-gray-600/20 text-gray-500'
                      }`}>
                      {user.enabled !== false ? '启用' : '禁用'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Info Section */}
              <div className="p-4 space-y-3">
                {/* Token Preview */}
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500 flex items-center gap-1">
                    <Key size={12} /> Token
                  </span>
                  <span className="text-xs font-mono text-gray-400 bg-gray-800 px-2 py-0.5 rounded">
                    {user.token || '****...'}
                  </span>
                </div>

                {/* Expire Time */}
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500 flex items-center gap-1">
                    <Calendar size={12} /> 到期时间
                  </span>
                  <span className={`text-xs font-medium ${user.expire_time && user.expire_time !== 0 && new Date(user.expire_time * 1000) < new Date()
                    ? 'text-red-400'
                    : 'text-gray-300'
                    }`}>
                    {formatExpire(user.expire_time)}
                  </span>
                </div>

                {/* Created At */}
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500 flex items-center gap-1">
                    <Clock size={12} /> 创建时间
                  </span>
                  <span className="text-xs text-gray-400">
                    {user.created_at ? new Date(user.created_at * 1000).toLocaleDateString('zh-CN') : '-'}
                  </span>
                </div>

                {/* Template */}
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">使用模版</span>
                  <span className="text-xs text-purple-400">
                    {getTemplateName(user.template_id)}
                  </span>
                </div>

                {/* Allocations Info - placeholder */}
                <div className="pt-2 border-t border-gray-700/30">
                  <span className="text-xs text-gray-500">节点分配</span>
                  <p className="text-sm text-blue-400 mt-1">
                    {user.allocations && Object.keys(user.allocations).length > 0
                      ? `${Object.keys(user.allocations).length} 个来源`
                      : '未分配节点'}
                  </p>
                </div>
              </div>

              {/* Actions Footer */}
              <div className="px-4 py-3 bg-gray-800/30 border-t border-gray-700/30 flex items-center justify-between">
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => onCopyUrl(user)}
                    className="p-2 text-gray-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors"
                    title="复制订阅地址"
                  >
                    <Copy size={16} />
                  </button>
                  <button
                    onClick={() => onToggle(user.id, user.enabled !== false)}
                    className={`p-2 rounded-lg transition-colors ${user.enabled !== false
                      ? 'text-green-400 hover:bg-green-500/10'
                      : 'text-gray-500 hover:bg-gray-700'
                      }`}
                    title={user.enabled !== false ? '禁用' : '启用'}
                  >
                    {user.enabled !== false ? <ToggleRight size={16} /> : <ToggleLeft size={16} />}
                  </button>
                  <button
                    onClick={() => setTokenUser(user)}
                    className="p-2 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded-lg transition-colors"
                    title="重新生成Token"
                  >
                    <Key size={16} />
                  </button>
                  <button
                    onClick={() => setEditingUser(user)}
                    className="p-2 text-gray-400 hover:text-purple-400 hover:bg-purple-500/10 rounded-lg transition-colors"
                    title="编辑分配"
                  >
                    <Edit2 size={16} />
                  </button>
                  <button
                    onClick={() => setConfigUser(user)}
                    disabled={!user.template_id || user.template_id === 'builtin'}
                    className={`p-2 rounded-lg transition-colors ${
                      !user.template_id || user.template_id === 'builtin'
                        ? 'text-gray-600 cursor-not-allowed'
                        : 'text-gray-400 hover:text-green-400 hover:bg-green-500/10'
                    }`}
                    title={!user.template_id || user.template_id === 'builtin' ? '内置模版不支持可视化编辑' : '配置节点'}
                  >
                    <Sliders size={16} />
                  </button>
                  <button
                    onClick={() => setSettingsUser(user)}
                    className="p-2 text-gray-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors"
                    title="用户设置"
                  >
                    <Settings size={16} />
                  </button>
                </div>
                <button
                  onClick={() => onDelete(user.id)}
                  className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                  title="删除"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
          ))
        ) : (
          <div className="col-span-full bg-gray-800/50 border border-gray-700 rounded-xl p-12 text-center">
            <UsersIcon size={48} className="mx-auto text-gray-600 mb-4" />
            <p className="text-gray-400 mb-4">还没有添加任何用户</p>
            <button
              onClick={() => setShowAddModal(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
            >
              添加第一个用户
            </button>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md mx-4">
            <h2 className="text-xl font-bold text-white mb-4">添加用户</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">用户名</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="输入用户名"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">过期时间（可选）</label>
                <input
                  type="date"
                  value={newExpire}
                  onChange={(e) => setNewExpire(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                取消
              </button>
              <button
                onClick={handleAdd}
                disabled={!newName.trim()}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                添加
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Allocation Modal */}
      {editingUser && (
        <AllocationModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          showToast={showToast || ((msg) => alert(msg))}
        />
      )}

      {/* Token Modal */}
      {tokenUser && (
        <TokenModal
          user={tokenUser}
          onClose={() => setTokenUser(null)}
          showToast={showToast || ((msg) => alert(msg))}
          onSuccess={() => onRefreshUsers && onRefreshUsers()}
        />
      )}

      {/* User Settings Modal */}
      {settingsUser && (
        <UserSettingsModal
          user={settingsUser}
          onClose={() => setSettingsUser(null)}
          showToast={showToast || ((msg) => alert(msg))}
          onSuccess={() => onRefreshUsers && onRefreshUsers()}
        />
      )}

      {/* User Config Editor */}
      {configUser && (
        <UserConfigEditor
          user={configUser}
          onClose={() => setConfigUser(null)}
          onSave={() => onRefreshUsers && onRefreshUsers()}
          showToast={showToast || ((msg, type) => alert(msg))}
        />
      )}
    </div>
  );
}
