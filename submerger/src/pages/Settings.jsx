import React, { useState, useEffect, useRef } from 'react';
import { Key, Globe, RefreshCw, Copy, Check, Eye, EyeOff, AlertCircle, CheckCircle, Plus, Trash2, Edit2, X, FileCode, Shuffle, Play, Sliders, Shield } from 'lucide-react';
import request, { isRequestCanceled } from '../utils/request';
import { copyToClipboard } from '../utils/clipboard';
import { formatDate } from '../utils/format';
import ConfirmModal from '../components/ConfirmModal';
import UserConfigEditor from '../components/UserConfigEditor';
import SocksExportModal from '../components/SocksExportModal';

const API_BASE = '/api';

const shouldIgnoreRequest = (err, signal) => signal?.aborted || isRequestCanceled(err);

const translationFieldLabels = {
  api_key: 'API Key',
  secret_key: 'Secret Key',
  secret_id: 'Secret ID',
  model: '模型',
  region: '区域',
  endpoint: '接口地址'
};

const translationSecretFields = new Set([
  'api_key', 'secret_key', 'secret_id'
]);

// Proxy Node Settings Component
// Subscription Proxy Settings Component
const SubscriptionProxySection = ({ showToast }) => {
  const [proxyUrl, setProxyUrl] = useState('');
  const [hasStoredProxy, setHasStoredProxy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    fetchData(controller.signal);
    return () => controller.abort();
  }, []);

  const fetchData = async (signal) => {
    setLoading(true);
    try {
      const res = await request.get(`${API_BASE}/settings/subscription-proxy`, { signal });
      if (signal?.aborted) return;
      setHasStoredProxy(Boolean(res.data.has_proxy_url));
      setProxyUrl(res.data.proxy_url || '');
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  };

  const saveSetting = async () => {
    if (!proxyUrl.trim()) {
      showToast?.('请输入新的代理地址；清除已有配置请使用“清除”按钮', 'error');
      return;
    }
    setSaving(true);
    try {
      await request.put(`${API_BASE}/settings/subscription-proxy`, { proxy_url: proxyUrl.trim() });
      setHasStoredProxy(true);
      showToast?.('代理设置已保存');
    } catch (err) {
      showToast?.('保存失败', 'error');
    } finally {
      setSaving(false);
    }
  };

  const clearSetting = async () => {
    setSaving(true);
    try {
      await request.put(`${API_BASE}/settings/subscription-proxy`, { proxy_url: null });
      setHasStoredProxy(false);
      setProxyUrl('');
      setTestResult(null);
      showToast?.('代理设置已清除');
    } catch (err) {
      showToast?.('清除失败', 'error');
    } finally {
      setSaving(false);
    }
  };

  const testProxy = async () => {
    if (!proxyUrl) {
      showToast?.('请先填写代理地址', 'error');
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const res = await request.post(`${API_BASE}/settings/ipv6-proxy/test`, { proxy_url: proxyUrl });
      setTestResult(res.data);
    } catch (err) {
      setTestResult({ status: 'error', message: err.response?.data?.detail || '测试失败' });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Shield size={20} />
        订阅获取代理
      </h2>

      {loading ? (
        <div className="text-center py-4 text-gray-500">加载中...</div>
      ) : (
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">代理地址</label>
            <input
              type="text"
              value={proxyUrl}
              onChange={(e) => setProxyUrl(e.target.value)}
              placeholder="socks5://warp:1080 或 http://proxy:8080"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">
              支持 socks5://、http:// 和 https://
            </p>
          </div>

          <div className="flex gap-3">
            <button
              onClick={saveSetting}
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              {saving ? '保存中...' : '保存'}
            </button>
            {hasStoredProxy && (
              <button
                onClick={clearSetting}
                disabled={saving}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                清除
              </button>
            )}
            <button
              onClick={testProxy}
              disabled={testing || !proxyUrl}
              className="px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              {testing ? '测试中...' : '测试代理'}
            </button>
          </div>

          {testResult && (
            <div className={`p-3 rounded-lg ${
              testResult.status === 'success' ? 'bg-green-900/30 border border-green-700' : 'bg-red-900/30 border border-red-700'
            }`}>
              <div className="text-sm font-mono">
                {testResult.status === 'success' ? (
                  <div className="text-green-300">
                    <div>✓ 代理可用</div>
                    {testResult.ip && (
                      <div className="text-xs text-green-400 mt-1">出口 IP: {testResult.ip}</div>
                    )}
                  </div>
                ) : (
                  <div className="text-red-300">✗ {testResult.message}</div>
                )}
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
  const [showSocksExportModal, setShowSocksExportModal] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetchData(controller.signal);
    return () => controller.abort();
  }, []);

  const fetchData = async (signal) => {
    setLoading(true);
    try {
      const [tokensRes, templatesRes] = await Promise.all([
        request.get(`${API_BASE}/admin-tokens`, { signal }),
        request.get(`${API_BASE}/templates`, { signal })
      ]);
      if (signal?.aborted) return;
      setTokens(tokensRes.data.tokens || []);
      setTemplates(templatesRes.data.templates || []);
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
      console.error('Failed to fetch data', err);
    } finally {
      if (!signal?.aborted) {
        setLoading(false);
      }
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
      const copied = await copyToClipboard(res.data.token);
      showToast?.(copied ? '新 Token 已复制到剪贴板' : 'Token 已重新生成，请手动复制');
    } catch (err) {
      showToast?.('重新生成失败', 'error');
    }
  };

  const copySubUrl = async (tokenId, format, socksOptions = null) => {
    try {
      // Fetch full token from API
      const res = await request.get(`${API_BASE}/admin-tokens/${tokenId}`);
      const fullToken = res.data.token.token;
      let url = `${window.location.origin}/sub?token=${encodeURIComponent(fullToken)}`;
      url += `&format=${format}`;
      if (format === 'socks' && socksOptions) {
        url += `&start_port=${encodeURIComponent(socksOptions.startPort)}`;
        if (socksOptions.excludePorts) {
          url += `&exclude_ports=${encodeURIComponent(socksOptions.excludePorts)}`;
        }
      }
      const copied = await copyToClipboard(url);
      if (!copied) {
        throw new Error('clipboard unavailable');
      }
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
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    setNewTokenValue(Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''));
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
                onClick={() => copySubUrl(showFormatSelector, 'v2ray')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">V2Ray</div>
                <div className="text-xs text-gray-400 mt-1">用于导入 v2rayN 的订阅格式</div>
              </button>
              <button
                onClick={() => copySubUrl(showFormatSelector, 'clash')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">Clash</div>
                <div className="text-xs text-gray-400 mt-1">标准Clash配置格式</div>
              </button>
              <button
                onClick={() => copySubUrl(showFormatSelector, 'singbox')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">Sing-box</div>
                <div className="text-xs text-gray-400 mt-1">Sing-box JSON 配置格式</div>
              </button>
              <button
                onClick={() => setShowSocksExportModal(true)}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">SOCKS</div>
                <div className="text-xs text-gray-400 mt-1">所有节点自动分配端口</div>
              </button>
            </div>
          </div>
        </div>
      )}
      {showSocksExportModal && (
        <SocksExportModal
          onClose={() => setShowSocksExportModal(false)}
          onConfirm={(options) => {
            copySubUrl(showFormatSelector, 'socks', options);
            setShowSocksExportModal(false);
          }}
        />
      )}
    </div>
  );
};

export default function Settings({
  onChangePassword,
  showToast
}) {
  const [speedtestConfig, setSpeedtestConfig] = useState({});
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // Online GeoIP API config
  const [onlineGeoipConfig, setOnlineGeoipConfig] = useState({
    preferred_api: 'ip-api.com',
    has_ipinfo_token: false,
    has_radar_token: false,
    apis: []
  });
  const [savingOnlineConfig, setSavingOnlineConfig] = useState(false);
  const [cloudflareRadarToken, setCloudflareRadarToken] = useState('');
  const [vpnGateConfig, setVpnGateConfig] = useState({
    enabled: false,
    interval_minutes: 60,
    max_nodes: 100,
    status: {},
    next_refresh_at: null
  });
  const [savingVpnGate, setSavingVpnGate] = useState(false);
  const [refreshingVpnGate, setRefreshingVpnGate] = useState(false);
  const [translationConfig, setTranslationConfig] = useState({
    preferred_provider: 'google',
    provider_order: [],
    providers: []
  });
  const [translationInputs, setTranslationInputs] = useState({});
  const [savingTranslation, setSavingTranslation] = useState(false);
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
  const geoipFilterResetTimer = useRef(null);

  useEffect(() => {
    const controller = new AbortController();
    fetchSpeedtestConfig(controller.signal);
    fetchOnlineGeoipConfig(controller.signal);
    fetchVpnGateConfig(controller.signal);
    fetchTranslationConfig(controller.signal);
    fetchGeoipCacheStats(controller.signal);
    return () => {
      controller.abort();
      if (geoipFilterResetTimer.current) {
        clearTimeout(geoipFilterResetTimer.current);
      }
    };
  }, []);

  const fetchSpeedtestConfig = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/speedtest/config`, { signal });
      if (signal?.aborted) return;
      setSpeedtestConfig(res.data);
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
      console.error('Failed to fetch speedtest config', err);
    }
  };

  const fetchOnlineGeoipConfig = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/geoip/online-config`, { signal });
      if (signal?.aborted) return;
      setOnlineGeoipConfig(res.data);
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
      console.error('Failed to fetch online GeoIP config', err);
    }
  };

  const fetchVpnGateConfig = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/vpngate/config`, { signal });
      if (signal?.aborted) return;
      setVpnGateConfig(res.data);
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
      console.error('Failed to fetch VPN Gate config', err);
    }
  };

  const fetchTranslationConfig = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/translation/config`, { signal });
      if (signal?.aborted) return;
      setTranslationConfig(res.data);
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
      console.error('Failed to fetch translation config', err);
    }
  };

  const fetchGeoipCacheStats = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/geoip/cache/stats`, { signal });
      if (signal?.aborted) return;
      setGeoipCacheStats(res.data);
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
      console.error('Failed to fetch GeoIP cache stats', err);
    }
  };

  const fetchGeoipCacheEntries = async (signal, filters = geoipCacheFilters) => {
    if (!signal?.aborted) {
      setGeoipCacheLoading(true);
    }
    try {
      const params = new URLSearchParams();
      params.set('limit', '200');
      if (filters.q) params.set('q', filters.q);
      if (filters.api_id && filters.api_id !== 'all') params.set('api_id', filters.api_id);
      if (filters.status && filters.status !== 'all') params.set('status', filters.status);
      if (filters.max_age) params.set('max_age', filters.max_age);
      if (filters.sort) params.set('sort', filters.sort);
      const res = await request.get(`${API_BASE}/geoip/cache/entries?${params.toString()}`, { signal });
      if (signal?.aborted) return;
      setGeoipCacheEntries(res.data.entries || []);
    } catch (err) {
      if (shouldIgnoreRequest(err, signal)) return;
      console.error('Failed to fetch GeoIP cache entries', err);
    } finally {
      if (!signal?.aborted) {
        setGeoipCacheLoading(false);
      }
    }
  };

  const refreshGeoipCache = async (signal, filters = geoipCacheFilters, expanded = geoipCacheExpanded) => {
    await fetchGeoipCacheStats(signal);
    if (signal?.aborted) return;
    if (expanded) {
      await fetchGeoipCacheEntries(signal, filters);
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
    const controller = new AbortController();
    const filtersSnapshot = { ...geoipCacheFilters };
    const timer = setInterval(() => {
      refreshGeoipCache(controller.signal, filtersSnapshot, true);
    }, intervalMs);
    return () => {
      clearInterval(timer);
      controller.abort();
    };
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

  const saveCloudflareRadarToken = async () => {
    const token = cloudflareRadarToken.trim();
    if (!token) {
      showToast?.('请输入 Cloudflare Radar API Token；清除已有配置请点击“清除”', 'error');
      return;
    }
    setSavingOnlineConfig(true);
    try {
      await request.post(`${API_BASE}/geoip/online-config`, {
        cloudflare_radar_token: token,
      });
      setCloudflareRadarToken('');
      showToast?.('Cloudflare Radar Token 已保存');
      await fetchOnlineGeoipConfig();
    } catch (err) {
      showToast?.(`保存失败: ${err.response?.data?.detail || err.message}`, 'error');
    } finally {
      setSavingOnlineConfig(false);
    }
  };

  const clearCloudflareRadarToken = async () => {
    setSavingOnlineConfig(true);
    try {
      await request.post(`${API_BASE}/geoip/online-config`, {
        cloudflare_radar_token: '',
      });
      setCloudflareRadarToken('');
      showToast?.('Cloudflare Radar Token 已清除');
      await fetchOnlineGeoipConfig();
    } catch (err) {
      showToast?.(`清除失败: ${err.response?.data?.detail || err.message}`, 'error');
    } finally {
      setSavingOnlineConfig(false);
    }
  };

  const saveVpnGateConfig = async (updates) => {
    setSavingVpnGate(true);
    try {
      const res = await request.put(`${API_BASE}/vpngate/config`, updates);
      setVpnGateConfig(res.data);
      showToast?.('VPN Gate 设置已保存');
    } catch (err) {
      showToast?.(`保存失败: ${err.response?.data?.detail || err.message}`, 'error');
    } finally {
      setSavingVpnGate(false);
    }
  };

  const refreshVpnGate = async () => {
    setRefreshingVpnGate(true);
    try {
      await request.post(`${API_BASE}/vpngate/refresh`);
      await fetchVpnGateConfig();
      showToast?.('VPN Gate 节点已更新');
    } catch (err) {
      await fetchVpnGateConfig();
      showToast?.(`VPN Gate 更新失败: ${err.response?.data?.detail || err.message}`, 'error');
    } finally {
      setRefreshingVpnGate(false);
    }
  };

  const saveTranslationSettings = async (providerId, updates) => {
    setSavingTranslation(true);
    try {
      const providerUpdates = { ...updates };
      Object.keys(providerUpdates).forEach((fieldName) => {
        if (typeof providerUpdates[fieldName] === 'string') {
          providerUpdates[fieldName] = providerUpdates[fieldName].trim();
        }
      });
      const res = await request.post(`${API_BASE}/translation/config`, {
        providers: { [providerId]: providerUpdates }
      });
      setTranslationConfig(res.data);
      setTranslationInputs(prev => ({ ...prev, [providerId]: {} }));
      showToast?.('翻译设置已保存');
    } catch (err) {
      showToast?.(`保存失败: ${err.response?.data?.detail || err.message}`, 'error');
    } finally {
      setSavingTranslation(false);
    }
  };

  const savePreferredTranslationProvider = async (providerId) => {
    setSavingTranslation(true);
    try {
      const res = await request.post(`${API_BASE}/translation/config`, {
        preferred_provider: providerId
      });
      setTranslationConfig(res.data);
      showToast?.('首选翻译服务已保存');
    } catch (err) {
      showToast?.(`保存失败: ${err.response?.data?.detail || err.message}`, 'error');
    } finally {
      setSavingTranslation(false);
    }
  };

  const toggleTranslationProvider = async (provider) => {
    await saveTranslationSettings(provider.id, { enabled: provider.enabled !== true });
  };

  const testTranslationProvider = async (providerId) => {
    try {
      await request.post(`${API_BASE}/translation/providers/${providerId}/test`, {
        text: 'Mountain View'
      });
      showToast?.('测试成功');
    } catch (err) {
      showToast?.(`测试失败: ${err.response?.data?.detail || err.message}`, 'error');
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
      // Secret values are never returned by the backend. Empty means unchanged.
      token: '',
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
        const testPayload = editingApi.id === 'ipinfo' && customApiForm.token
          ? { token: customApiForm.token }
          : {};
        const res = await request.post(`${API_BASE}/geoip/apis/${editingApi.id}/test`, testPayload);
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

  const formatFileSize = (bytes) => {
    if (!bytes) return '-';
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(2)} MB`;
  };

  const selectedTranslationProviderId = translationConfig.preferred_provider || 'google';

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">系统设置</h1>
        <p className="text-gray-400 text-sm mt-1">配置系统参数</p>
      </div>

      {/* Admin Token Management */}
      <AdminTokenSection showToast={showToast} />

      {/* IPv6 Proxy Settings */}
      <SubscriptionProxySection showToast={showToast} />

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

          <div className="flex items-center gap-3">
            <label className="text-sm text-gray-300" htmlFor="preferred-geoip-api">首选 API</label>
            <select
              id="preferred-geoip-api"
              value={onlineGeoipConfig.preferred_api || 'ip-api.com'}
              onChange={(event) => saveOnlineGeoipConfig(event.target.value)}
              disabled={savingOnlineConfig}
              className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm disabled:opacity-50"
            >
              {(onlineGeoipConfig.apis || [])
                .filter(api => api.enabled !== false)
                .map(api => <option key={api.id} value={api.id}>{api.name}</option>)}
            </select>
          </div>
          
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
                  <button
                    onClick={() => testGeoipApi(api.id)}
                    className="px-2 py-1 text-xs text-blue-300 hover:bg-gray-600 rounded transition-colors"
                  >
                    测试
                  </button>
                  <button
                    onClick={() => toggleApiEnabled(api.id, api.enabled !== false)}
                    className={`px-2 py-1 text-xs rounded transition-colors ${api.enabled !== false ? 'text-green-300 hover:bg-gray-600' : 'text-gray-400 hover:bg-gray-700'}`}
                  >
                    {api.enabled !== false ? '已启用' : '已禁用'}
                  </button>
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
                  onClick={() => refreshGeoipCache()}
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
                      onClick={() => fetchGeoipCacheEntries()}
                      className="px-2 py-1 text-xs bg-blue-500/20 text-blue-300 rounded hover:bg-blue-500/30"
                    >
                      筛选
                    </button>
                    <button
                      onClick={() => {
                        const resetFilters = { q: '', api_id: 'all', status: 'all', max_age: '', sort: 'newest' };
                        setGeoipCacheFilters(resetFilters);
                        if (geoipFilterResetTimer.current) {
                          clearTimeout(geoipFilterResetTimer.current);
                        }
                        geoipFilterResetTimer.current = setTimeout(() => fetchGeoipCacheEntries(undefined, resetFilters), 0);
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

      {/* Cloudflare Radar configuration */}
      <div id="cloudflare-radar-settings" className="bg-gray-800/50 border border-blue-500/30 rounded-xl p-6">
        <div className="flex items-start justify-between gap-3 mb-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Globe size={20} />
              Cloudflare Radar API
            </h2>
            <p className="text-sm text-gray-400 mt-2">
              填写 Cloudflare API Token 后，节点地区/IP 信息检测会按 ASN 查询人类/机器人流量参考值。
            </p>
          </div>
          <span className={`text-xs px-2 py-1 rounded whitespace-nowrap ${onlineGeoipConfig.has_radar_token
            ? 'bg-green-500/20 text-green-300'
            : 'bg-gray-700 text-gray-400'}`}>
            {onlineGeoipConfig.has_radar_token ? '已配置' : '未配置'}
          </span>
        </div>
        <div className="space-y-3">
          <label className="block text-sm text-gray-300" htmlFor="cloudflare-radar-token">
            Cloudflare API Token
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <input
              id="cloudflare-radar-token"
              type="password"
              value={cloudflareRadarToken}
              onChange={(event) => setCloudflareRadarToken(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') saveCloudflareRadarToken();
              }}
              placeholder={onlineGeoipConfig.has_radar_token ? '已配置，输入新 Token 可覆盖' : '粘贴 Cloudflare API Token'}
              autoComplete="new-password"
              className="flex-1 min-w-[260px] px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm placeholder-gray-500 focus:outline-none focus:border-blue-500"
              disabled={savingOnlineConfig}
            />
            <button
              onClick={saveCloudflareRadarToken}
              disabled={savingOnlineConfig || !cloudflareRadarToken.trim()}
              className="px-3 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm rounded-lg"
            >
              保存 Token
            </button>
            {onlineGeoipConfig.has_radar_token && (
              <button
                onClick={clearCloudflareRadarToken}
                disabled={savingOnlineConfig}
                className="px-3 py-2 bg-gray-700 hover:bg-gray-600 disabled:text-gray-500 text-gray-200 text-sm rounded-lg"
              >
                清除
              </button>
            )}
          </div>
          <p className="text-xs text-gray-500">
            Token 只保存在后端，不会回显到前端；保存后重新执行“地区/IP 信息检测”，节点表才会填充人机流量比。
          </p>
        </div>
      </div>

      {/* VPN Gate dynamic node source */}
      <div className="bg-gray-800/50 border border-emerald-500/30 rounded-xl p-6">
        <div className="flex items-start justify-between gap-3 mb-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Globe size={20} />
              VPN Gate 节点源
            </h2>
            <p className="text-sm text-gray-400 mt-2">
              自动下载 VPN Gate 的 OpenVPN 节点，可在创建链式代理时作为落地节点或落地池使用。
            </p>
          </div>
          <span className={`text-xs px-2 py-1 rounded whitespace-nowrap ${vpnGateConfig.enabled
            ? 'bg-green-500/20 text-green-300'
            : 'bg-gray-700 text-gray-400'}`}>
            {vpnGateConfig.enabled ? '自动更新已启用' : '自动更新已停用'}
          </span>
        </div>

        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-4">
            <label className="inline-flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={vpnGateConfig.enabled === true}
                onChange={(event) => saveVpnGateConfig({ enabled: event.target.checked })}
                disabled={savingVpnGate || refreshingVpnGate}
                className="h-4 w-4 rounded border-gray-600 bg-gray-700 text-emerald-500 focus:ring-emerald-500"
              />
              自动更新
            </label>

            <label className="flex items-center gap-2 text-sm text-gray-300" htmlFor="vpngate-interval">
              更新间隔
              <select
                id="vpngate-interval"
                value={vpnGateConfig.interval_minutes || 60}
                onChange={(event) => saveVpnGateConfig({ interval_minutes: Number(event.target.value) })}
                disabled={savingVpnGate || refreshingVpnGate}
                className="px-2 py-1.5 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm disabled:opacity-50"
              >
                <option value={15}>15 分钟</option>
                <option value={30}>30 分钟</option>
                <option value={60}>1 小时</option>
                <option value={360}>6 小时</option>
                <option value={1440}>每天</option>
                <option value={10080}>每周</option>
              </select>
            </label>

            <button
              onClick={refreshVpnGate}
              disabled={refreshingVpnGate || savingVpnGate}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm rounded-lg"
            >
              <RefreshCw size={15} className={refreshingVpnGate ? 'animate-spin' : ''} />
              {refreshingVpnGate ? '更新中...' : '立即更新'}
            </button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div className="rounded-lg bg-gray-700/40 px-3 py-2">
              <div className="text-xs text-gray-500">当前有效节点</div>
              <div className="text-white mt-1">{vpnGateConfig.status?.active_node_count ?? 0}</div>
            </div>
            <div className="rounded-lg bg-gray-700/40 px-3 py-2">
              <div className="text-xs text-gray-500">失效节点</div>
              <div className="text-white mt-1">{vpnGateConfig.status?.stale_node_count ?? 0}</div>
            </div>
            <div className="rounded-lg bg-gray-700/40 px-3 py-2">
              <div className="text-xs text-gray-500">最近成功</div>
              <div className="text-white mt-1">{formatDate(vpnGateConfig.status?.last_success_at) || '暂无'}</div>
            </div>
            <div className="rounded-lg bg-gray-700/40 px-3 py-2">
              <div className="text-xs text-gray-500">下次更新</div>
              <div className="text-white mt-1">{formatDate(vpnGateConfig.next_refresh_at) || '未安排'}</div>
            </div>
          </div>

          {vpnGateConfig.status?.last_error && (
            <div className="text-sm text-red-300 bg-red-900/20 border border-red-700/50 rounded-lg px-3 py-2 break-words">
              最近一次更新失败：{vpnGateConfig.status.last_error}
            </div>
          )}
          <p className="text-xs text-gray-500">
            最多缓存 {vpnGateConfig.max_nodes || 100} 个节点；更新失败时继续使用上一份缓存。
          </p>
        </div>
      </div>

      {/* Location translation providers */}
      <div className="bg-gray-800/50 border border-purple-500/30 rounded-xl p-6">
        <div className="flex items-start justify-between gap-3 mb-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Globe size={20} />
              地点名称翻译 API
            </h2>
            <p className="text-sm text-gray-400 mt-2">
              将 GeoIP 返回的英文国家、地区和城市名称翻译为简体中文。已是中文的结果不会重复请求。
            </p>
          </div>
          <span className="text-xs px-2 py-1 rounded bg-purple-500/20 text-purple-300 whitespace-nowrap">
            支持多供应商降级
          </span>
        </div>

        <div className="flex items-center gap-3 mb-4">
          <label className="text-sm text-gray-300" htmlFor="preferred-translation-provider">首选服务</label>
          <select
            id="preferred-translation-provider"
            value={translationConfig.preferred_provider || 'google'}
            onChange={(event) => savePreferredTranslationProvider(event.target.value)}
            disabled={savingTranslation}
            className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm disabled:opacity-50"
          >
            {(translationConfig.providers || []).map(provider => (
              <option key={provider.id} value={provider.id}>
                {provider.name}{provider.configured ? '' : '（未配置）'}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-3">
          {(translationConfig.providers || []).filter(provider => provider.id === selectedTranslationProviderId).map(provider => {
            const pendingValues = translationInputs[provider.id] || {};
            return (
              <div key={provider.id} className="p-3 rounded-lg bg-gray-700/40 border border-gray-600">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-white font-medium">{provider.name}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded ${provider.configured ? 'bg-green-500/20 text-green-300' : 'bg-gray-600 text-gray-400'}`}>
                        {provider.configured ? '已配置' : '未配置'}
                      </span>
                      {provider.id === translationConfig.preferred_provider && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300">首选</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      onClick={() => testTranslationProvider(provider.id)}
                      disabled={!provider.configured || savingTranslation}
                      className="px-2 py-1 text-xs text-blue-300 hover:bg-gray-600 disabled:text-gray-500 rounded"
                    >
                      测试
                    </button>
                    <button
                      onClick={() => toggleTranslationProvider(provider)}
                      disabled={savingTranslation || (!provider.enabled && !provider.configured)}
                      className={`px-2 py-1 text-xs rounded ${provider.enabled ? 'text-green-300 hover:bg-gray-600' : 'text-gray-400 hover:bg-gray-700'}`}
                    >
                      {provider.enabled ? '已启用' : '已禁用'}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3">
                  {(provider.fields || []).map(fieldName => {
                    const isSecret = translationSecretFields.has(fieldName);
                    return (
                      <div key={fieldName}>
                        <label className="block text-xs text-gray-400 mb-1">
                          {translationFieldLabels[fieldName] || fieldName}
                        </label>
                        <input
                          type={isSecret ? 'password' : 'text'}
                          value={pendingValues[fieldName] || ''}
                          onChange={(event) => setTranslationInputs(prev => ({
                            ...prev,
                            [provider.id]: {
                              ...(prev[provider.id] || {}),
                              [fieldName]: event.target.value
                            }
                          }))}
                          placeholder={isSecret && provider.has_credentials ? '已配置，留空保持不变' : (provider[fieldName] || '')}
                          autoComplete="new-password"
                          className="w-full px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-white text-xs placeholder-gray-600 focus:outline-none focus:border-purple-500"
                          disabled={savingTranslation}
                        />
                      </div>
                    );
                  })}
                </div>
                <div className="flex justify-end mt-3">
                  <button
                    onClick={() => saveTranslationSettings(provider.id, pendingValues)}
                    disabled={savingTranslation || Object.keys(pendingValues).length === 0}
                    className="px-3 py-1.5 text-xs bg-purple-600 hover:bg-purple-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded"
                  >
                    保存此服务
                  </button>
                </div>
              </div>
            );
          })}
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
                    type="password"
                    autoComplete="new-password"
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
                {(!editingApi?.builtin || editingApi?.id === 'ipinfo') && (
                  <button
                    onClick={saveCustomApi}
                    disabled={
                      savingOnlineConfig
                      || (!editingApi?.builtin && (!customApiForm.name || !customApiForm.url || !customApiTestResult?.success))
                      || (editingApi?.id === 'ipinfo' && !customApiForm.token && !editingApi?.has_token)
                    }
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
                    title={!editingApi?.builtin && !customApiTestResult?.success ? '请先测试成功后再保存' : ''}
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

      {/* Password Settings */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Key size={20} />
          安全设置
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">修改密码</label>
            <div className="grid gap-2 md:grid-cols-[1fr_1fr_auto]">
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="输入当前密码"
                  autoComplete="current-password"
                  className="w-full px-3 py-2 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="输入新密码"
                  autoComplete="new-password"
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
                onClick={async () => {
                  const changed = await onChangePassword(currentPassword, newPassword);
                  if (changed) {
                    setCurrentPassword('');
                    setNewPassword('');
                  }
                }}
                disabled={!currentPassword.trim() || !newPassword.trim()}
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
