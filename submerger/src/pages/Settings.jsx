import React, { useState, useEffect } from 'react';
import { Key, Globe, RefreshCw, Copy, Check, Eye, EyeOff, AlertCircle, CheckCircle, Plus, Trash2, Edit2, X, FileCode, Shuffle, Play, Sliders, Shield } from 'lucide-react';
import request from '../utils/request';
import ConfirmModal from '../components/ConfirmModal';
import UserConfigEditor from '../components/UserConfigEditor';

const API_BASE = '/api';

// Proxy Node Settings Component
const ProxyNodeSection = ({ showToast }) => {
  const [proxyNodeSetting, setProxyNodeSetting] = useState({ proxy_node_id: null, proxy_node_name: null });
  const [availableNodes, setAvailableNodes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [settingRes, nodesRes] = await Promise.all([
        request.get(`${API_BASE}/settings/proxy-node`),
        request.get(`${API_BASE}/settings/available-proxy-nodes`)
      ]);
      setProxyNodeSetting(settingRes.data);
      setAvailableNodes(nodesRes.data.nodes || []);
    } catch (err) {
      console.error('Failed to fetch proxy node settings', err);
    } finally {
      setLoading(false);
    }
  };

  const saveProxyNode = async (nodeId, nodeName) => {
    setSaving(true);
    try {
      await request.put(`${API_BASE}/settings/proxy-node`, {
        proxy_node_id: nodeId,
        proxy_node_name: nodeName
      });
      setProxyNodeSetting({ proxy_node_id: nodeId, proxy_node_name: nodeName });
      showToast?.('代理节点设置已保存');
    } catch (err) {
      showToast?.('保存失败', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleNodeChange = (e) => {
    const nodeId = e.target.value;
    if (nodeId === '') {
      saveProxyNode(null, null);
    } else {
      const node = availableNodes.find(n => n.id === nodeId);
      if (node) {
        saveProxyNode(nodeId, node.name);
      }
    }
  };

  // Group nodes by source
  const groupedNodes = availableNodes.reduce((acc, node) => {
    const source = node.source === 'custom' ? '自建节点' : node.source.replace('subscription:', '订阅: ');
    if (!acc[source]) acc[source] = [];
    acc[source].push(node);
    return acc;
  }, {});

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Shield size={20} />
          订阅获取代理设置
        </h2>
      </div>

      <p className="text-xs text-gray-400 mb-4">
        当订阅直连失败时，自动使用此节点作为代理获取订阅内容
      </p>

      {loading ? (
        <div className="text-center py-4 text-gray-500">加载中...</div>
      ) : (
        <div>
          <label className="block text-sm text-gray-400 mb-2">代理节点</label>
          <select
            value={proxyNodeSetting.proxy_node_id || ''}
            onChange={handleNodeChange}
            disabled={saving}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500 disabled:opacity-50"
          >
            <option value="">不使用代理</option>
            {Object.entries(groupedNodes).map(([source, nodes]) => (
              <optgroup key={source} label={source}>
                {nodes.map(node => (
                  <option key={node.id} value={node.id}>
                    {node.display_name || node.name}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>

          {proxyNodeSetting.proxy_node_id && (
            <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
              <div className="flex items-start gap-2">
                <CheckCircle size={16} className="text-blue-400 mt-0.5 flex-shrink-0" />
                <div className="text-sm text-blue-300">
                  <p className="font-medium">当前使用: {proxyNodeSetting.proxy_node_name}</p>
                  <p className="text-xs text-blue-400 mt-1">
                    订阅刷新时会先尝试直连，失败后自动切换到此代理节点
                  </p>
                </div>
              </div>
            </div>
          )}

          {availableNodes.length === 0 && (
            <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
              <div className="flex items-start gap-2">
                <AlertCircle size={16} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                <div className="text-sm text-yellow-300">
                  <p>没有可用的节点</p>
                  <p className="text-xs text-yellow-400 mt-1">
                    请先添加自建节点或订阅，然后才能选择代理节点
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Admin Token Management Component
const AdminTokenSection = ({ showToast }) => {
  const [tokens, setTokens] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingToken, setEditingToken] = useState(null);
  const [newTokenName, setNewTokenName] = useState('');
  const [newTokenValue, setNewTokenValue] = useState('');
  const [newTokenTemplate, setNewTokenTemplate] = useState('builtin');
  const [newSubFilename, setNewSubFilename] = useState('');
  const [newSubName, setNewSubName] = useState('');
  const [useCustomToken, setUseCustomToken] = useState(false);
  const [saving, setSaving] = useState(false);
  const [copiedId, setCopiedId] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);  // Token ID to delete
  const [configToken, setConfigToken] = useState(null);  // Token for visual config editor
  const [showFormatSelector, setShowFormatSelector] = useState(null);  // Token ID for format selector

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [tokensRes, templatesRes] = await Promise.all([
        request.get(`${API_BASE}/admin-tokens`),
        request.get(`${API_BASE}/templates`)
      ]);
      setTokens(tokensRes.data.tokens || []);
      setTemplates(templatesRes.data.templates || []);
    } catch (err) {
      console.error('Failed to fetch data', err);
    } finally {
      setLoading(false);
    }
  };

  const createToken = async () => {
    if (!newTokenName.trim()) {
      showToast?.('请输入名称', 'error');
      return;
    }
    if (useCustomToken && newTokenValue.trim().length < 8) {
      showToast?.('自定义 Token 至少需要 8 个字符', 'error');
      return;
    }

    setSaving(true);
    try {
      await request.post(`${API_BASE}/admin-tokens`, {
        name: newTokenName.trim(),
        template_id: newTokenTemplate,
        custom_token: useCustomToken ? newTokenValue.trim() : null,
        sub_filename: newSubFilename.trim() || null,
        sub_name: newSubName.trim() || null
      });
      showToast?.('Token 创建成功');
      resetForm();
      setShowCreateModal(false);
      fetchData();
    } catch (err) {
      showToast?.('创建失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSaving(false);
    }
  };

  const deleteToken = async (tokenId) => {
    try {
      await request.delete(`${API_BASE}/admin-tokens/${tokenId}`);
      showToast?.('Token 已删除');
      fetchData();
    } catch (err) {
      showToast?.('删除失败', 'error');
    }
    setDeleteConfirm(null);
  };

  const toggleTokenStatus = async (token) => {
    try {
      await request.put(`${API_BASE}/admin-tokens/${token.id}`, {
        enabled: !(token.enabled !== false)
      });
      fetchData();
      showToast?.(token.enabled !== false ? 'Token 已禁用' : 'Token 已启用');
    } catch (err) {
      showToast?.('状态更新失败', 'error');
    }
  };

  const regenerateToken = async (tokenId) => {
    try {
      const res = await request.post(`${API_BASE}/admin-tokens/${tokenId}/regenerate`);
      showToast?.('Token 已重新生成');
      fetchData();
      // Copy new token to clipboard
      navigator.clipboard.writeText(res.data.token);
      showToast?.('新 Token 已复制到剪贴板');
    } catch (err) {
      showToast?.('重新生成失败', 'error');
    }
  };

  const copySubUrl = async (tokenId, format = 'base64') => {
    try {
      // Fetch full token from API
      const res = await request.get(`${API_BASE}/admin-tokens/${tokenId}`);
      const fullToken = res.data.token.token;
      let url = `${window.location.origin}/sub?token=${fullToken}`;
      url += `&format=${format}`;
      navigator.clipboard.writeText(url);
      setCopiedId(tokenId);
      setShowFormatSelector(null);
      setTimeout(() => setCopiedId(null), 2000);
      showToast?.('订阅地址已复制');
    } catch (err) {
      showToast?.('复制失败', 'error');
    }
  };

  const openVisualEditor = (token) => {
    // Open visual config editor for admin token
    setConfigToken(token);
  };

  const resetForm = () => {
    setNewTokenName('');
    setNewTokenValue('');
    setNewTokenTemplate('builtin');
    setNewSubFilename('');
    setNewSubName('');
    setUseCustomToken(false);
    setEditingToken(null);
  };

  const generateRandomToken = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 32; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setNewTokenValue(token);
  };

  const getTemplateName = (templateId) => {
    if (!templateId || templateId === 'builtin') return '内置模版';
    const template = templates.find(t => t.id === templateId);
    return template ? template.name : templateId;
  };

  const openEditModal = async (token) => {
    // Fetch full token details
    try {
      const res = await request.get(`${API_BASE}/admin-tokens/${token.id}`);
      const fullToken = res.data.token;
      setEditingToken(fullToken);
      setNewTokenName(fullToken.name || '');
      setNewTokenTemplate(fullToken.template_id || 'builtin');
      setNewSubFilename(fullToken.sub_filename || '');
      setNewSubName(fullToken.sub_name || '');
      setShowEditModal(true);
    } catch (err) {
      showToast?.('获取 Token 详情失败', 'error');
    }
  };

  const updateToken = async () => {
    if (!editingToken) return;

    setSaving(true);
    try {
      await request.put(`${API_BASE}/admin-tokens/${editingToken.id}`, {
        name: newTokenName.trim(),
        template_id: newTokenTemplate,
        sub_filename: newSubFilename.trim() || '',
        sub_name: newSubName.trim() || ''
      });
      showToast?.('Token 更新成功');
      resetForm();
      setShowEditModal(false);
      fetchData();
    } catch (err) {
      showToast?.('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Key size={20} />
          管理员订阅 Token
        </h2>
        <button
          onClick={() => {
            resetForm();
            setShowCreateModal(true);
          }}
          className="flex items-center gap-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors"
        >
          <Plus size={16} />
          新建 Token
        </button>
      </div>

      <p className="text-xs text-gray-500 mb-4">
        创建多个管理员订阅 Token，每个可以使用不同的模版。
      </p>

      {loading ? (
        <div className="text-center py-4 text-gray-500">加载中...</div>
      ) : tokens.length === 0 ? (
        <div className="text-center py-8 text-gray-500">
          <Key size={32} className="mx-auto mb-2 opacity-50" />
          <p>还没有创建管理员 Token</p>
          <p className="text-xs mt-1">点击"新建 Token"开始</p>
        </div>
      ) : (
        <div className="space-y-3">
          {tokens.map((token) => (
            <div
              key={token.id}
              className="bg-gray-700/50 rounded-lg p-4 flex items-center justify-between"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-white font-medium">{token.name}</span>
                  <span
                    onClick={() => toggleTokenStatus(token)}
                    className={`px-2 py-0.5 text-xs rounded cursor-pointer select-none transition-colors ${token.enabled !== false
                      ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                      : 'bg-gray-600/20 text-gray-500 hover:bg-gray-600/30'
                      }`}
                  >
                    {token.enabled !== false ? '启用' : '禁用'}
                  </span>
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  <span className="font-mono">{token.token}</span>
                </div>
                <div className="text-xs text-gray-500 mt-1 flex items-center gap-2">
                  <FileCode size={12} />
                  模版: {getTemplateName(token.template_id)}
                </div>
              </div>

              <div className="flex items-center gap-2 ml-4">
                <button
                  onClick={() => setShowFormatSelector(token.id)}
                  className="p-2 text-gray-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors"
                  title="复制订阅地址"
                >
                  {copiedId === token.id ? <Check size={16} /> : <Copy size={16} />}
                </button>
                <button
                  onClick={() => openVisualEditor(token)}
                  disabled={token.template_id === 'builtin'}
                  className={`p-2 rounded-lg transition-colors ${
                    token.template_id === 'builtin'
                      ? 'text-gray-600 cursor-not-allowed'
                      : 'text-gray-400 hover:text-green-400 hover:bg-green-500/10'
                  }`}
                  title={token.template_id === 'builtin' ? '内置模版不支持可视化编辑' : '可视化编辑'}
                >
                  <Sliders size={16} />
                </button>
                <button
                  onClick={() => openEditModal(token)}
                  className="p-2 text-gray-400 hover:text-purple-400 hover:bg-purple-500/10 rounded-lg transition-colors"
                  title="编辑设置"
                >
                  <Edit2 size={16} />
                </button>
                <button
                  onClick={() => regenerateToken(token.id)}
                  className="p-2 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded-lg transition-colors"
                  title="重新生成 Token"
                >
                  <RefreshCw size={16} />
                </button>
                <button
                  onClick={() => setDeleteConfirm(token.id)}
                  className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                  title="删除"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="text-lg font-bold text-white">新建管理员 Token</h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-gray-400 hover:text-white"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2">名称</label>
                <input
                  type="text"
                  value={newTokenName}
                  onChange={(e) => setNewTokenName(e.target.value)}
                  placeholder="例如：测试设备"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">使用模版</label>
                <select
                  value={newTokenTemplate}
                  onChange={(e) => setNewTokenTemplate(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  {templates.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <div className="flex items-center gap-2 mb-2">
                  <input
                    type="checkbox"
                    id="useCustomToken"
                    checked={useCustomToken}
                    onChange={(e) => setUseCustomToken(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-600"
                  />
                  <label htmlFor="useCustomToken" className="text-sm text-gray-400">
                    自定义 Token 值
                  </label>
                </div>

                {useCustomToken && (
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={newTokenValue}
                      onChange={(e) => setNewTokenValue(e.target.value)}
                      placeholder="至少 8 个字符"
                      className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white font-mono text-sm focus:outline-none focus:border-blue-500"
                    />
                    <button
                      onClick={generateRandomToken}
                      className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-400 rounded-lg transition-colors"
                      title="生成随机值"
                    >
                      <Shuffle size={18} />
                    </button>
                  </div>
                )}
              </div>

              <div className="border-t border-gray-700 pt-4">
                <p className="text-xs text-gray-500 mb-3">订阅设置（可选，留空使用全局设置）</p>
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">配置名称</label>
                    <input
                      type="text"
                      value={newSubName}
                      onChange={(e) => setNewSubName(e.target.value)}
                      placeholder="客户端显示的配置名称"
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">订阅文件名</label>
                    <input
                      type="text"
                      value={newSubFilename}
                      onChange={(e) => setNewSubFilename(e.target.value)}
                      placeholder="下载时的文件名"
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="px-6 py-4 border-t border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                取消
              </button>
              <button
                onClick={createToken}
                disabled={saving}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {saving ? '创建中...' : '创建'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEditModal && editingToken && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="text-lg font-bold text-white">编辑管理员 Token</h3>
              <button
                onClick={() => { setShowEditModal(false); resetForm(); }}
                className="text-gray-400 hover:text-white"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2">名称</label>
                <input
                  type="text"
                  value={newTokenName}
                  onChange={(e) => setNewTokenName(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">使用模版</label>
                <select
                  value={newTokenTemplate}
                  onChange={(e) => setNewTokenTemplate(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  {templates.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              </div>

              <div className="border-t border-gray-700 pt-4">
                <p className="text-xs text-gray-500 mb-3">订阅设置（留空使用全局设置）</p>
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">配置名称</label>
                    <input
                      type="text"
                      value={newSubName}
                      onChange={(e) => setNewSubName(e.target.value)}
                      placeholder="客户端显示的配置名称"
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">订阅文件名</label>
                    <input
                      type="text"
                      value={newSubFilename}
                      onChange={(e) => setNewSubFilename(e.target.value)}
                      placeholder="下载时的文件名"
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="px-6 py-4 border-t border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => { setShowEditModal(false); resetForm(); }}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                取消
              </button>
              <button
                onClick={updateToken}
                disabled={saving}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {saving ? '保存中...' : '保存'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl p-6 max-w-sm mx-4">
            <h3 className="text-lg font-bold text-white mb-2">确认删除</h3>
            <p className="text-gray-400 text-sm mb-4">确定要删除这个 Token 吗？删除后无法恢复。</p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={() => deleteToken(deleteConfirm)}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors"
              >
                删除
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Visual Config Editor */}
      {configToken && (
        <UserConfigEditor
          user={{
            id: configToken.id,
            name: configToken.name,
            template_id: configToken.template_id,
            allocations: {},  // Admin tokens don't have allocations
            group_config: configToken.group_config || {}
          }}
          onClose={() => setConfigToken(null)}
          onSave={() => {
            fetchData();  // Refresh token list
          }}
          showToast={showToast}
          isAdminToken={true}
        />
      )}

      {/* Format Selector Popup */}
      {showFormatSelector && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={() => setShowFormatSelector(null)}>
          <div className="bg-gray-800 rounded-xl p-6 w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-white">选择格式</h3>
              <button onClick={() => setShowFormatSelector(null)} className="text-gray-400 hover:text-white">
                <X size={18} />
              </button>
            </div>
            <div className="space-y-2">
              <button
                onClick={() => copySubUrl(showFormatSelector, 'base64')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">Base64</div>
                <div className="text-xs text-gray-400 mt-1">通用订阅格式</div>
              </button>
              <button
                onClick={() => copySubUrl(showFormatSelector, 'clash')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">Clash</div>
                <div className="text-xs text-gray-400 mt-1">标准Clash配置格式</div>
              </button>
              <button
                onClick={() => copySubUrl(showFormatSelector, 'socks')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">SOCKS (自动)</div>
                <div className="text-xs text-gray-400 mt-1">所有节点自动分配端口（从42000开始）</div>
              </button>
              <button
                onClick={() => copySubUrl(showFormatSelector, 'socks-manual')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">SOCKS (手动)</div>
                <div className="text-xs text-gray-400 mt-1">仅使用手动配置的端口映射</div>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default function Settings({
  onChangePassword,
  showToast
}) {
  const [speedtestConfig, setSpeedtestConfig] = useState({});
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // Online GeoIP API config
  const [onlineGeoipConfig, setOnlineGeoipConfig] = useState({
    preferred_api: 'ip-api.com',
    ipinfo_token: '',
    apis: []
  });
  const [ipinfoToken, setIpinfoToken] = useState('');
  const [savingOnlineConfig, setSavingOnlineConfig] = useState(false);
  const [showAddApiModal, setShowAddApiModal] = useState(false);
  const [editingApi, setEditingApi] = useState(null);
  const [deleteApiConfirm, setDeleteApiConfirm] = useState(null);
  const [customApiForm, setCustomApiForm] = useState({
    name: '',
    url: '',
    token: '',
    limit: '',
    test_ip: '8.8.8.8',
    country_code_path: '',
    country_name_path: '',
    city_path: '',
    success_check: ''
  });
  const [configApiId, setConfigApiId] = useState(null);  // For builtin API config modal (e.g., ipinfo token)
  const [customApiTestResult, setCustomApiTestResult] = useState(null);  // Test result for custom API
  const [testingCustomApi, setTestingCustomApi] = useState(false);  // Testing custom API in progress
  const [geoipCacheStats, setGeoipCacheStats] = useState(null);
  const [geoipCacheEntries, setGeoipCacheEntries] = useState([]);
  const [geoipCacheLoading, setGeoipCacheLoading] = useState(false);
  const [geoipCacheExpanded, setGeoipCacheExpanded] = useState(false);
  const [geoipCacheFilters, setGeoipCacheFilters] = useState({
    q: '',
    api_id: 'all',
    status: 'all',
    max_age: '',
    sort: 'newest'
  });
  const [geoipAutoRefresh, setGeoipAutoRefresh] = useState('off');

  useEffect(() => {
    fetchSpeedtestConfig();
    fetchOnlineGeoipConfig();
    fetchGeoipCacheStats();
  }, []);

  const fetchSpeedtestConfig = async () => {
    try {
      const res = await request.get(`${API_BASE}/speedtest/config`);
      setSpeedtestConfig(res.data);
    } catch (err) {
      console.error('Failed to fetch speedtest config', err);
    }
  };

  const fetchOnlineGeoipConfig = async () => {
    try {
      const res = await request.get(`${API_BASE}/geoip/online-config`);
      setOnlineGeoipConfig(res.data);
      setIpinfoToken(res.data.ipinfo_token || '');
    } catch (err) {
      console.error('Failed to fetch online GeoIP config', err);
    }
  };

  const fetchGeoipCacheStats = async () => {
    try {
      const res = await request.get(`${API_BASE}/geoip/cache/stats`);
      setGeoipCacheStats(res.data);
    } catch (err) {
      console.error('Failed to fetch GeoIP cache stats', err);
    }
  };

  const fetchGeoipCacheEntries = async () => {
    setGeoipCacheLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('limit', '200');
      if (geoipCacheFilters.q) params.set('q', geoipCacheFilters.q);
      if (geoipCacheFilters.api_id && geoipCacheFilters.api_id !== 'all') params.set('api_id', geoipCacheFilters.api_id);
      if (geoipCacheFilters.status && geoipCacheFilters.status !== 'all') params.set('status', geoipCacheFilters.status);
      if (geoipCacheFilters.max_age) params.set('max_age', geoipCacheFilters.max_age);
      if (geoipCacheFilters.sort) params.set('sort', geoipCacheFilters.sort);
      const res = await request.get(`${API_BASE}/geoip/cache/entries?${params.toString()}`);
      setGeoipCacheEntries(res.data.entries || []);
    } catch (err) {
      console.error('Failed to fetch GeoIP cache entries', err);
    } finally {
      setGeoipCacheLoading(false);
    }
  };

  const refreshGeoipCache = async () => {
    await fetchGeoipCacheStats();
    if (geoipCacheExpanded) {
      await fetchGeoipCacheEntries();
    }
  };

  const exportGeoipCache = async (format) => {
    try {
      const params = new URLSearchParams();
      params.set('format', format);
      if (geoipCacheFilters.q) params.set('q', geoipCacheFilters.q);
      if (geoipCacheFilters.api_id && geoipCacheFilters.api_id !== 'all') params.set('api_id', geoipCacheFilters.api_id);
      if (geoipCacheFilters.status && geoipCacheFilters.status !== 'all') params.set('status', geoipCacheFilters.status);
      if (geoipCacheFilters.max_age) params.set('max_age', geoipCacheFilters.max_age);
      if (geoipCacheFilters.sort) params.set('sort', geoipCacheFilters.sort);
      const res = await request.get(`${API_BASE}/geoip/cache/export?${params.toString()}`, { responseType: 'blob' });
      const blob = new Blob([res.data], { type: format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `geoip-cache-${Date.now()}.${format === 'csv' ? 'csv' : 'json'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      showToast?.('导出失败', 'error');
    }
  };

  const clearGeoipCache = async () => {
    try {
      await request.post(`${API_BASE}/geoip/cache/clear`);
      showToast?.('GeoIP 缓存已清空');
      setGeoipCacheEntries([]);
      fetchGeoipCacheStats();
    } catch (err) {
      showToast?.('清空缓存失败', 'error');
    }
  };

  useEffect(() => {
    if (!geoipCacheExpanded || geoipAutoRefresh === 'off') return;
    const intervalMs = parseInt(geoipAutoRefresh, 10);
    if (!intervalMs) return;
    const timer = setInterval(() => {
      refreshGeoipCache();
    }, intervalMs);
    return () => clearInterval(timer);
  }, [geoipCacheExpanded, geoipAutoRefresh, geoipCacheFilters]);

  const saveOnlineGeoipConfig = async (preferredApi = null, token = null) => {
    setSavingOnlineConfig(true);
    try {
      const payload = {};
      if (preferredApi !== null) payload.preferred_api = preferredApi;
      if (token !== null) payload.ipinfo_token = token;
      
      await request.post(`${API_BASE}/geoip/online-config`, payload);
      showToast('设置已保存');
      fetchOnlineGeoipConfig();
    } catch (err) {
      showToast('保存失败', 'error');
    } finally {
      setSavingOnlineConfig(false);
    }
  };

  const testGeoipApi = async (apiId) => {
    try {
      const res = await request.post(`${API_BASE}/geoip/apis/${apiId}/test`);
      if (res.data.success) {
        const r = res.data.result;
        showToast(`测试成功: ${r.country} (${r.countryCode}) ${r.city || ''}`);
      } else {
        showToast(`测试失败: ${res.data.error}`, 'error');
      }
    } catch (err) {
      showToast('测试失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const toggleApiEnabled = async (apiId, currentEnabled) => {
    try {
      await request.post(`${API_BASE}/geoip/apis/${apiId}/toggle`, { enabled: !currentEnabled });
      fetchOnlineGeoipConfig();
      showToast(currentEnabled ? 'API 已禁用' : 'API 已启用');
    } catch (err) {
      showToast('操作失败', 'error');
    }
  };

  const openEditApiModal = (api) => {
    setEditingApi(api);
    
    // For builtin APIs, set their URL templates
    let url = api.url || '';
    if (api.builtin) {
      if (api.id === 'ip-api.com') {
        url = 'http://ip-api.com/json/{ip}?lang=zh-CN';
      } else if (api.id === 'ipwhois') {
        url = 'https://ipwhois.app/json/{ip}?lang=zh-CN';
      } else if (api.id === 'ipinfo') {
        url = 'https://ipinfo.io/{ip}/json?token={key}';
      }
    }
    
    setCustomApiForm({
      name: api.name || '',
      url: url,
      // Don't load token for security - user can enter new one if needed
      // For ipinfo builtin, load from global config; for custom APIs, leave empty
      token: api.id === 'ipinfo' ? (onlineGeoipConfig.ipinfo_token || '') : '',
      test_ip: '8.8.8.8',
      country_code_path: api.country_code_path || '',
      country_name_path: api.country_name_path || '',
      city_path: api.city_path || '',
      success_check: api.success_check || '',
      limit: api.limit || ''  // Load limit field
    });
    setCustomApiTestResult(null);
  };

  const closeApiModal = () => {
    setShowAddApiModal(false);
    setEditingApi(null);
    setCustomApiForm({
      name: '',
      url: '',
      token: '',
      test_ip: '8.8.8.8',
      country_code_path: '',
      country_name_path: '',
      city_path: '',
      success_check: '',
      limit: ''
    });
    setCustomApiTestResult(null);
  };

  const testCustomApi = async () => {
    if (!customApiForm.url) {
      showToast('请填写接口地址', 'error');
      return;
    }
    
    setTestingCustomApi(true);
    setCustomApiTestResult(null);
    
    try {
      // For builtin APIs, use the existing test endpoint
      if (editingApi?.builtin) {
        // For ipinfo, save token first if changed
        if (editingApi.id === 'ipinfo' && customApiForm.token !== onlineGeoipConfig.ipinfo_token) {
          await saveOnlineGeoipConfig(null, customApiForm.token);
        }
        
        const res = await request.post(`${API_BASE}/geoip/apis/${editingApi.id}/test`, {
          test_ip: customApiForm.test_ip || '8.8.8.8'
        });
        setCustomApiTestResult(res.data);
      } else if (editingApi && !customApiForm.token && editingApi.has_token) {
        // Editing existing custom API without new token - use saved API's token via API ID
        const res = await request.post(`${API_BASE}/geoip/apis/${editingApi.id}/test`, {
          test_ip: customApiForm.test_ip || '8.8.8.8'
        });
        setCustomApiTestResult(res.data);
      } else {
        // New custom API or editing with new token
        const res = await request.post(`${API_BASE}/geoip/test-custom-api`, {
          url: customApiForm.url,
          token: customApiForm.token || '',
          country_code_path: customApiForm.country_code_path || '',
          country_name_path: customApiForm.country_name_path || '',
          city_path: customApiForm.city_path || '',
          success_check: customApiForm.success_check || '',
          test_ip: customApiForm.test_ip || '8.8.8.8'
        });
        setCustomApiTestResult(res.data);
      }
    } catch (err) {
      setCustomApiTestResult({
        success: false,
        error: err.response?.data?.detail || err.message
      });
    } finally {
      setTestingCustomApi(false);
    }
  };

  const saveCustomApi = async () => {
    setSavingOnlineConfig(true);
    try {
      // Build payload - only include token if user entered a new one
      const payload = { ...customApiForm };
      if (editingApi && !payload.token) {
        // Don't send empty token when editing - keep existing
        delete payload.token;
      }
      
      if (editingApi) {
        await request.put(`${API_BASE}/geoip/apis/${editingApi.id}`, payload);
        showToast('API 已更新');
      } else {
        await request.post(`${API_BASE}/geoip/apis`, payload);
        showToast('API 已添加');
      }
      closeApiModal();
      fetchOnlineGeoipConfig();
    } catch (err) {
      showToast('保存失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSavingOnlineConfig(false);
    }
  };

  const deleteCustomApi = async (apiId) => {
    try {
      await request.delete(`${API_BASE}/geoip/apis/${apiId}`);
      showToast('API 已删除');
      fetchOnlineGeoipConfig();
    } catch (err) {
      showToast('删除失败', 'error');
    }
    setDeleteApiConfirm(null);
  };

  const copySubUrl = () => {
    const url = `${window.location.origin}/sub?token=${subToken}`;
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return '-';
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">系统设置</h1>
        <p className="text-gray-400 text-sm mt-1">配置系统参数</p>
      </div>

      {/* Admin Token Management */}
      <AdminTokenSection showToast={showToast} />

      {/* Online GeoIP API Settings */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Globe size={20} />
          在线 IP 查询 API
        </h2>
        
        <div className="space-y-4">
          <p className="text-sm text-gray-400">
            节点地区检测时使用在线 API 查询出口 IP 的地理位置
          </p>
          
          {/* API List */}
          <div className="space-y-2">
            {(onlineGeoipConfig.apis || []).map(api => (
              <div
                key={api.id}
                className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer ${
                  api.enabled !== false
                    ? 'bg-gray-700/50 border border-gray-600 hover:border-gray-500'
                    : 'bg-gray-800/50 border border-gray-700 opacity-60'
                }`}
                onClick={() => openEditApiModal(api)}
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-white font-medium">{api.name}</span>
                    {api.builtin ? (
                      <span className="text-xs px-1.5 py-0.5 bg-blue-600/30 text-blue-400 rounded">内置</span>
                    ) : (
                      <span className="text-xs px-1.5 py-0.5 bg-purple-600/30 text-purple-400 rounded">自定义</span>
                    )}
                    {api.limit && (
                      <span className="text-xs px-1.5 py-0.5 bg-gray-600 rounded text-gray-300">{api.limit}</span>
                    )}
                  </div>
                  {api.description && (
                    <div className="text-xs text-gray-400 mt-0.5">{api.description}</div>
                  )}
                  {!api.builtin && api.url && (
                    <div className="text-xs text-gray-500 mt-0.5 truncate max-w-md">{api.url}</div>
                  )}
                </div>
                
                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  {/* Delete button for custom APIs */}
                  {!api.builtin && (
                    <button
                      onClick={() => setDeleteApiConfirm(api.id)}
                      className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-600 rounded transition-colors"
                      title="删除"
                    >
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* GeoIP Cache */}
          <div className="mt-4 p-4 bg-gray-900/40 border border-gray-700 rounded-lg">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-300 font-medium">GeoIP 缓存</div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => exportGeoipCache('csv')}
                  className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-white rounded"
                >
                  导出 CSV
                </button>
                <button
                  onClick={() => exportGeoipCache('json')}
                  className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-white rounded"
                >
                  导出 JSON
                </button>
                <button
                  onClick={refreshGeoipCache}
                  className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-white rounded"
                >
                  刷新
                </button>
                <button
                  onClick={clearGeoipCache}
                  className="px-2 py-1 text-xs bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded"
                >
                  清空
                </button>
                <button
                  onClick={async () => {
                    const next = !geoipCacheExpanded;
                    setGeoipCacheExpanded(next);
                    if (next) {
                      await fetchGeoipCacheEntries();
                    }
                  }}
                  className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-white rounded"
                >
                  {geoipCacheExpanded ? '收起' : '展开'}
                </button>
              </div>
            </div>
            <div className="mt-2 text-xs text-gray-400 flex flex-wrap gap-4">
              <span>缓存条数: {geoipCacheStats?.cache_size ?? '-'}</span>
              <span>有效: {geoipCacheStats?.positive ?? '-'}</span>
              <span>负缓存: {geoipCacheStats?.negative ?? '-'}</span>
            </div>

            {geoipCacheExpanded && (
              <div className="mt-3 max-h-64 overflow-y-auto border border-gray-700 rounded-lg">
                <div className="p-3 border-b border-gray-700 bg-gray-800/70">
                  <div className="grid grid-cols-12 gap-2">
                    <input
                      value={geoipCacheFilters.q}
                      onChange={(e) => setGeoipCacheFilters(prev => ({ ...prev, q: e.target.value }))}
                      placeholder="搜索 IP/地区/城市"
                      className="col-span-12 md:col-span-4 px-2 py-1 text-xs bg-gray-800 border border-gray-700 rounded text-white focus:outline-none focus:border-blue-500"
                    />
                    <select
                      value={geoipCacheFilters.api_id}
                      onChange={(e) => setGeoipCacheFilters(prev => ({ ...prev, api_id: e.target.value }))}
                      className="col-span-6 md:col-span-3 px-2 py-1 text-xs bg-gray-800 border border-gray-700 rounded text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="all">全部 API</option>
                      {(onlineGeoipConfig.apis || []).map(api => (
                        <option key={api.id} value={api.id}>{api.name || api.id}</option>
                      ))}
                    </select>
                    <select
                      value={geoipCacheFilters.status}
                      onChange={(e) => setGeoipCacheFilters(prev => ({ ...prev, status: e.target.value }))}
                      className="col-span-6 md:col-span-3 px-2 py-1 text-xs bg-gray-800 border border-gray-700 rounded text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="all">全部状态</option>
                      <option value="positive">命中</option>
                      <option value="negative">负缓存</option>
                    </select>
                    <select
                      value={geoipCacheFilters.max_age}
                      onChange={(e) => setGeoipCacheFilters(prev => ({ ...prev, max_age: e.target.value }))}
                      className="col-span-6 md:col-span-2 px-2 py-1 text-xs bg-gray-800 border border-gray-700 rounded text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="">不限时间</option>
                      <option value="300">5分钟内</option>
                      <option value="1800">30分钟内</option>
                      <option value="3600">1小时内</option>
                      <option value="21600">6小时内</option>
                      <option value="86400">24小时内</option>
                      <option value="604800">7天内</option>
                    </select>
                    <select
                      value={geoipCacheFilters.sort}
                      onChange={(e) => setGeoipCacheFilters(prev => ({ ...prev, sort: e.target.value }))}
                      className="col-span-6 md:col-span-2 px-2 py-1 text-xs bg-gray-800 border border-gray-700 rounded text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="newest">最新优先</option>
                      <option value="oldest">最旧优先</option>
                      <option value="age_desc">年龄最长</option>
                    </select>
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <button
                      onClick={fetchGeoipCacheEntries}
                      className="px-2 py-1 text-xs bg-blue-500/20 text-blue-300 rounded hover:bg-blue-500/30"
                    >
                      筛选
                    </button>
                    <button
                      onClick={() => {
                        setGeoipCacheFilters({ q: '', api_id: 'all', status: 'all', max_age: '', sort: 'newest' });
                        setTimeout(fetchGeoipCacheEntries, 0);
                      }}
                      className="px-2 py-1 text-xs bg-gray-700 text-gray-200 rounded hover:bg-gray-600"
                    >
                      重置
                    </button>
                    <select
                      value={geoipAutoRefresh}
                      onChange={(e) => setGeoipAutoRefresh(e.target.value)}
                      className="ml-auto px-2 py-1 text-xs bg-gray-800 border border-gray-700 rounded text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="off">自动刷新: 关闭</option>
                      <option value="10000">自动刷新: 10秒</option>
                      <option value="30000">自动刷新: 30秒</option>
                      <option value="60000">自动刷新: 60秒</option>
                    </select>
                  </div>
                </div>
                {geoipCacheLoading ? (
                  <div className="p-3 text-xs text-gray-400">加载中...</div>
                ) : (
                  <table className="w-full text-xs text-gray-300">
                    <thead className="sticky top-0 bg-gray-800 text-gray-400">
                      <tr>
                        <th className="text-left px-3 py-2">IP</th>
                        <th className="text-left px-3 py-2">地区</th>
                        <th className="text-left px-3 py-2">API</th>
                        <th className="text-left px-3 py-2">年龄</th>
                        <th className="text-left px-3 py-2">状态</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(geoipCacheEntries || []).map((entry, idx) => (
                        <tr key={`${entry.ip}-${entry.api_id}-${idx}`} className="border-t border-gray-700">
                          <td className="px-3 py-2 truncate max-w-[200px]">{entry.ip}</td>
                          <td className="px-3 py-2">
                            {entry.negative ? '-' : `${entry.flag || ''} ${entry.country || ''} ${entry.city || ''}`}
                          </td>
                          <td className="px-3 py-2">{entry.api_id}</td>
                          <td className="px-3 py-2">{entry.age != null ? `${entry.age}s` : '-'}</td>
                          <td className="px-3 py-2">
                            {entry.negative ? (
                              <span className="text-gray-500">负缓存</span>
                            ) : (
                              <span className="text-green-400">命中</span>
                            )}
                          </td>
                        </tr>
                      ))}
                      {(!geoipCacheEntries || geoipCacheEntries.length === 0) && (
                        <tr>
                          <td className="px-3 py-3 text-gray-500" colSpan={5}>暂无缓存记录</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </div>
          
          {/* Add custom API button */}
          <button
            onClick={() => setShowAddApiModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
          >
            <Plus size={18} />
            添加自定义 API
          </button>
        </div>
      </div>

      {/* Add/Edit Custom API Modal */}
      {(showAddApiModal || editingApi) && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">
                {editingApi?.builtin ? `${editingApi.name} 配置` : (editingApi ? '编辑自定义 API' : '添加自定义 API')}
              </h3>
              <button onClick={closeApiModal} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>
            
            <div className="space-y-4">
              {/* 1. Name */}
              <div>
                <label className="block text-sm text-gray-400 mb-1">名称</label>
                <input
                  type="text"
                  value={customApiForm.name}
                  onChange={(e) => setCustomApiForm({...customApiForm, name: e.target.value})}
                  placeholder="例如: ipgeolocation.io"
                  disabled={editingApi?.builtin}
                  className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 ${editingApi?.builtin ? 'opacity-60 cursor-not-allowed' : ''}`}
                />
              </div>
              
              {/* 2. API URL */}
              <div>
                <label className="block text-sm text-gray-400 mb-1">
                  接口地址
                  <span className="text-gray-500 ml-1">（用 {'{ip}'} 和 {'{key}'} 作为占位符）</span>
                </label>
                <input
                  type="text"
                  value={customApiForm.url}
                  onChange={(e) => setCustomApiForm({...customApiForm, url: e.target.value})}
                  placeholder="例如: https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={ip}&lang=cn"
                  disabled={editingApi?.builtin}
                  className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono text-sm ${editingApi?.builtin ? 'opacity-60 cursor-not-allowed' : ''}`}
                />
              </div>
              
              {/* 3. Token/API Key (optional) */}
              {(!editingApi?.builtin || editingApi?.needs_token) && (
                <div>
                  <label className="block text-sm text-gray-400 mb-1">
                    Token / API Key
                    <span className="text-gray-500 ml-1">（可选，如不需要留空）</span>
                  </label>
                  <input
                    type="text"
                    value={customApiForm.token || ''}
                    onChange={(e) => setCustomApiForm({...customApiForm, token: e.target.value})}
                    placeholder={editingApi?.has_token ? '已配置，留空则不修改' : '如果API需要认证，填入Token或API Key'}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
                  />
                  {/* Preview URL - mask the key */}
                  {customApiForm.url && (
                    <p className="text-xs text-gray-500 mt-1 font-mono break-all">
                      预览: {customApiForm.url
                        .replace('{ip}', customApiForm.test_ip || '8.8.8.8')
                        .replace('{key}', (customApiForm.token || editingApi?.has_token) ? '***' : '')
                        .replace('{token}', (customApiForm.token || editingApi?.has_token) ? '***' : '')}
                    </p>
                  )}
                </div>
              )}
              
              {/* 4. Test IP */}
              <div>
                <label className="block text-sm text-gray-400 mb-1">测试 IP</label>
                <input
                  type="text"
                  value={customApiForm.test_ip || '8.8.8.8'}
                  onChange={(e) => setCustomApiForm({...customApiForm, test_ip: e.target.value})}
                  placeholder="8.8.8.8"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
                />
              </div>
              
              {/* 5. Usage Limit (custom APIs only) */}
              {!editingApi?.builtin && (
                <div>
                  <label className="block text-sm text-gray-400 mb-1">
                    用量限制
                    <span className="text-gray-500 ml-1">（可选，仅作显示用）</span>
                  </label>
                  <input
                    type="text"
                    value={customApiForm.limit || ''}
                    onChange={(e) => setCustomApiForm({...customApiForm, limit: e.target.value})}
                    placeholder="例如: 1000次/天 或 30000次/月"
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-sm"
                  />
                </div>
              )}
              
              {/* Test Result */}
              {customApiTestResult && (
                <div className={`p-3 rounded-lg ${customApiTestResult.success ? 'bg-green-500/10 border border-green-500/30' : 'bg-red-500/10 border border-red-500/30'}`}>
                  {customApiTestResult.success ? (
                    <div className="space-y-2">
                      <div className="text-green-400 text-sm flex items-center gap-2">
                        <CheckCircle size={16} />
                        <span>测试成功: {customApiTestResult.result?.country} ({customApiTestResult.result?.countryCode}) {customApiTestResult.result?.city || ''}</span>
                      </div>
                      {customApiTestResult.raw_response && (
                        <details className="text-xs">
                          <summary className="text-gray-400 cursor-pointer hover:text-gray-300">查看原始响应</summary>
                          <pre className="mt-2 p-2 bg-gray-900/50 rounded text-gray-300 overflow-x-auto max-h-40 overflow-y-auto">
                            {JSON.stringify(customApiTestResult.raw_response, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  ) : (
                    <div className="text-red-400 text-sm">
                      <AlertCircle size={16} className="inline mr-2" />
                      测试失败: {customApiTestResult.error}
                    </div>
                  )}
                </div>
              )}
            </div>
            
            <div className="flex justify-between gap-2 mt-6">
              <button
                onClick={testCustomApi}
                disabled={testingCustomApi || !customApiForm.url}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                <Play size={16} className={testingCustomApi ? 'animate-pulse' : ''} />
                {testingCustomApi ? '测试中...' : '测试'}
              </button>
              <div className="flex gap-2">
                <button
                  onClick={closeApiModal}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  {editingApi?.builtin ? '关闭' : '取消'}
                </button>
                {!editingApi?.builtin && (
                  <button
                    onClick={saveCustomApi}
                    disabled={savingOnlineConfig || !customApiForm.name || !customApiForm.url || !customApiTestResult?.success}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
                    title={!customApiTestResult?.success ? '请先测试成功后再保存' : ''}
                  >
                    {savingOnlineConfig ? '保存中...' : '保存'}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete API Confirm Modal */}
      {deleteApiConfirm && (
        <ConfirmModal
          isOpen={!!deleteApiConfirm}
          title="删除 API"
          message="确定要删除这个自定义 API 吗？"
          onConfirm={() => deleteCustomApi(deleteApiConfirm)}
          onClose={() => setDeleteApiConfirm(null)}
          type="danger"
        />
      )}

      {/* Proxy Node Settings */}
      <ProxyNodeSection showToast={showToast} />

      {/* Password Settings */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Key size={20} />
          安全设置
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">修改密码</label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="输入新密码"
                  className="w-full px-3 py-2 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <button
                onClick={() => {
                  onChangePassword(newPassword);
                  setNewPassword('');
                }}
                disabled={!newPassword.trim()}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                修改
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-1">密码要求：至少8个字符，包含字母和数字</p>
          </div>
        </div>
      </div>
    </div>
  );
}
