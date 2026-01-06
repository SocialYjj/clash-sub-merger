import React, { useState, useEffect, useRef } from 'react';
import { FileCode, Upload, Save, RotateCcw, Plus, Trash2, Edit3, Copy, Check, X, Lock, ChevronDown, ChevronUp, Info } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

// 预设模板示例
const TEMPLATE_EXAMPLE = `# Clash 配置模板示例
# 上传文件会覆盖此内容

mixed-port: 7890
allow-lan: true
mode: rule
log-level: info

dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

proxies: []

# 在 proxies 列表中使用占位符，如 {{ALL_PROXIES}}
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - DIRECT
      - REJECT
      - 手动选择
      - {{COUNTRY_GROUPS}}

  - name: 手动选择
    type: select
    proxies:
      - {{ALL_PROXIES}}

  - name: 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
      - {{ALL_PROXIES}}

rules:
  - GEOIP,CN,DIRECT
  - MATCH,GLOBAL
`;

export default function Templates({ showToast }) {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [templateContent, setTemplateContent] = useState('');
  const [templateName, setTemplateName] = useState('');
  const [saving, setSaving] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [newTemplateName, setNewTemplateName] = useState('');
  const [creating, setCreating] = useState(false);
  const fileInputRef = useRef(null);
  const createFileInputRef = useRef(null);
  const [showPlaceholderHelp, setShowPlaceholderHelp] = useState(true);

  useEffect(() => {
    fetchTemplates();
  }, []);

  const fetchTemplates = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/templates`);
      setTemplates(res.data.templates || []);
    } catch (err) {
      console.error('Failed to fetch templates', err);
      showToast?.('加载模版列表失败', 'error');
    } finally {
      setLoading(false);
    }
  };

  const openTemplate = async (template) => {
    try {
      const res = await axios.get(`${API_BASE}/templates/${template.id}`);
      setSelectedTemplate(res.data);
      setTemplateContent(res.data.content || '');
      setTemplateName(res.data.name || '');
      setShowEditModal(true);
    } catch (err) {
      showToast?.('加载模版失败', 'error');
    }
  };

  const saveTemplate = async () => {
    if (!selectedTemplate) return;

    if (selectedTemplate.is_builtin) {
      showToast?.('内置模版不可修改', 'error');
      return;
    }

    setSaving(true);
    try {
      await axios.put(`${API_BASE}/templates/${selectedTemplate.id}`, {
        name: templateName,
        content: templateContent
      });
      showToast?.('模版已保存');
      setShowEditModal(false);
      fetchTemplates();
    } catch (err) {
      showToast?.('保存失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSaving(false);
    }
  };

  const deleteTemplate = async (template) => {
    if (template.is_builtin) {
      showToast?.('内置模版不可删除', 'error');
      return;
    }

    if (!confirm(`确定要删除模版 "${template.name}" 吗？`)) return;

    try {
      await axios.delete(`${API_BASE}/templates/${template.id}`);
      showToast?.('模版已删除');
      fetchTemplates();
    } catch (err) {
      showToast?.('删除失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleCreateFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      // Call backend API to parse and clean the uploaded file
      const formData = new FormData();
      formData.append('file', file);
      formData.append('current_template', '');

      const res = await axios.post(`${API_BASE}/template/parse`, formData);
      if (res.data?.content) {
        setTemplateContent(res.data.content);
        showToast?.('文件已导入并处理');
      }
    } catch (err) {
      // Fallback to raw file content if API fails
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result;
        if (typeof content === 'string') {
          setTemplateContent(content);
        }
      };
      reader.readAsText(file);
      showToast?.('文件导入成功（未处理）', 'warning');
    }

    if (createFileInputRef.current) {
      createFileInputRef.current.value = '';
    }
  };

  const createTemplate = async () => {
    if (!newTemplateName.trim()) {
      showToast?.('请输入模版名称', 'error');
      return;
    }

    // Get default template content if empty
    let content = templateContent;
    if (!content.trim()) {
      try {
        const res = await axios.get(`${API_BASE}/templates/builtin`);
        content = res.data.content || '';
      } catch (e) {
        content = 'port: 7890\nallow-lan: false\nmode: rule\n\nproxies: []\n\nproxy-groups: []\n\nrules:\n  - MATCH,DIRECT';
      }
    }

    setCreating(true);
    try {
      await axios.post(`${API_BASE}/templates`, {
        name: newTemplateName.trim(),
        content: content
      });
      showToast?.('模版创建成功');
      setShowCreateModal(false);
      setNewTemplateName('');
      setTemplateContent('');
      fetchTemplates();
    } catch (err) {
      showToast?.('创建失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setCreating(false);
    }
  };

  const copyTemplateId = (id) => {
    navigator.clipboard.writeText(id);
    showToast?.('模版 ID 已复制');
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return '内置';
    return new Date(timestamp * 1000).toLocaleDateString('zh-CN');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">模版管理</h1>
          <p className="text-gray-400 text-sm mt-1">管理多个 Clash 配置模版</p>
        </div>
        <button
          onClick={() => {
            setNewTemplateName('');
            setTemplateContent(TEMPLATE_EXAMPLE);
            setShowCreateModal(true);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
        >
          <Plus size={18} />
          新建模版
        </button>
      </div>

      {/* Templates Grid */}
      {loading ? (
        <div className="flex items-center justify-center h-64 text-gray-500">
          加载中...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {templates.map((template) => (
            <div
              key={template.id}
              className={`bg-gray-800/50 border rounded-xl p-5 transition-all hover:border-blue-500/50 ${template.is_builtin ? 'border-yellow-500/30' : 'border-gray-700'
                }`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FileCode size={20} className={template.is_builtin ? 'text-yellow-500' : 'text-blue-400'} />
                  <h3 className="text-white font-medium">{template.name}</h3>
                  {template.is_builtin && (
                    <span className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded">
                      <Lock size={10} className="inline mr-1" />
                      内置
                    </span>
                  )}
                </div>
              </div>

              <div className="text-xs text-gray-500 mb-4">
                <div className="flex items-center gap-2">
                  <span>ID: {template.id}</span>
                  <button
                    onClick={() => copyTemplateId(template.id)}
                    className="text-gray-400 hover:text-white transition-colors"
                    title="复制 ID"
                  >
                    <Copy size={12} />
                  </button>
                </div>
                <div className="mt-1">创建: {formatDate(template.created_at)}</div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => openTemplate(template)}
                  className="flex-1 flex items-center justify-center gap-1 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-lg transition-colors"
                >
                  <Edit3 size={14} />
                  {template.is_builtin ? '查看' : '编辑'}
                </button>
                {!template.is_builtin && (
                  <button
                    onClick={() => deleteTemplate(template)}
                    className="px-3 py-2 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded-lg transition-colors"
                    title="删除"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h2 className="text-xl font-bold text-white">新建模版</h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-6 overflow-y-auto flex-1 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2">模版名称</label>
                <input
                  type="text"
                  value={newTemplateName}
                  onChange={(e) => setNewTemplateName(e.target.value)}
                  placeholder="例如：精简模版"
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-gray-400">模版内容</label>
                  <div className="flex gap-2">
                    <input
                      ref={createFileInputRef}
                      type="file"
                      accept=".yaml,.yml"
                      onChange={handleCreateFileUpload}
                      className="hidden"
                    />
                    <button
                      onClick={() => createFileInputRef.current?.click()}
                      className="text-xs px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors"
                    >
                      <Upload size={12} className="inline mr-1" />
                      导入文件
                    </button>
                  </div>
                </div>

                {/* Placeholder Help for Create Modal */}
                <div className="mb-3 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                  <div className="flex items-center gap-2 text-blue-400 text-xs mb-2">
                    <Info size={14} />
                    <span className="font-medium">可用占位符</span>
                  </div>
                  <div className="grid grid-cols-3 gap-1 text-xs">
                    <code className="px-2 py-1 bg-gray-800 text-cyan-400 rounded">{`{{ALL_PROXIES}}`}</code>
                    <code className="px-2 py-1 bg-gray-800 text-cyan-400 rounded">{`{{COUNTRY_GROUPS}}`}</code>
                    <code className="px-2 py-1 bg-gray-800 text-cyan-400 rounded">{`{{HK}} {{US}} {{JP}}`}</code>
                  </div>
                </div>

                <textarea
                  value={templateContent}
                  onChange={(e) => setTemplateContent(e.target.value)}
                  placeholder="# 模板内容..."
                  className="w-full h-64 px-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-gray-300 font-mono text-sm resize-none focus:outline-none focus:border-blue-500"
                  spellCheck={false}
                />
              </div>
            </div>

            <div className="px-6 py-4 border-t border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={createTemplate}
                disabled={creating}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {creating ? '创建中...' : '创建'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEditModal && selectedTemplate && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-bold text-white">
                  {selectedTemplate.is_builtin ? '查看模版' : '编辑模版'}
                </h2>
                {selectedTemplate.is_builtin && (
                  <span className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded">
                    内置模版 (只读)
                  </span>
                )}
              </div>
              <button
                onClick={() => setShowEditModal(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-6 overflow-y-auto flex-1">
              <div className="flex gap-4">
                {/* Left: Editor */}
                <div className="flex-1 space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-2">模版名称</label>
                    <input
                      type="text"
                      value={templateName}
                      onChange={(e) => setTemplateName(e.target.value)}
                      disabled={selectedTemplate.is_builtin}
                      className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500 disabled:opacity-50"
                    />
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-2">模版内容</label>
                    <textarea
                      value={templateContent}
                      onChange={(e) => setTemplateContent(e.target.value)}
                      disabled={selectedTemplate.is_builtin}
                      className="w-full h-[400px] px-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-gray-300 font-mono text-sm resize-none focus:outline-none focus:border-blue-500 disabled:opacity-50"
                      spellCheck={false}
                    />
                  </div>
                </div>

                {/* Right: Placeholder Help (always visible for non-builtin) */}
                {!selectedTemplate.is_builtin && (
                  <div className="w-52 shrink-0">
                    <div className="sticky top-0 bg-gray-800/50 border border-blue-500/30 rounded-lg p-4">
                      <div className="flex items-center gap-2 text-blue-400 text-sm mb-3">
                        <Info size={16} />
                        <span className="font-medium">占位符</span>
                      </div>
                      <div className="space-y-2 text-xs">
                        <div className="bg-gray-900 px-3 py-2 rounded">
                          <code className="text-cyan-400 block">{`{{ALL_PROXIES}}`}</code>
                          <span className="text-gray-500">所有代理节点</span>
                        </div>
                        <div className="bg-gray-900 px-3 py-2 rounded">
                          <code className="text-cyan-400 block">{`{{COUNTRY_GROUPS}}`}</code>
                          <span className="text-gray-500">所有国家分组</span>
                        </div>
                        <div className="bg-gray-900 px-3 py-2 rounded">
                          <code className="text-cyan-400 block">{`{{HK}}`}</code>
                          <span className="text-gray-500">香港节点</span>
                        </div>
                        <div className="bg-gray-900 px-3 py-2 rounded">
                          <code className="text-cyan-400 block">{`{{US}}`}</code>
                          <span className="text-gray-500">美国节点</span>
                        </div>
                        <div className="bg-gray-900 px-3 py-2 rounded">
                          <code className="text-cyan-400 block">{`{{JP}}`}</code>
                          <span className="text-gray-500">日本节点</span>
                        </div>
                        <div className="bg-gray-900 px-3 py-2 rounded">
                          <code className="text-cyan-400 block">{`{{SG}}`}</code>
                          <span className="text-gray-500">新加坡节点</span>
                        </div>
                        <div className="bg-gray-900 px-3 py-2 rounded">
                          <code className="text-cyan-400 block">{`{{TW}} {{KR}} ...`}</code>
                          <span className="text-gray-500">其他国家代码</span>
                        </div>
                      </div>
                      <p className="text-xs text-gray-500 mt-3 italic">
                        在 proxies 列表中使用
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="px-6 py-4 border-t border-gray-700 flex justify-between">
              <div className="text-xs text-gray-500">
                {selectedTemplate.is_builtin
                  ? '内置模版自动按国家分组'
                  : '在 proxy-groups 中使用占位符，proxies 部分会自动填充'}
              </div>
              <div className="flex gap-3">
                <button
                  onClick={() => setShowEditModal(false)}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  {selectedTemplate.is_builtin ? '关闭' : '取消'}
                </button>
                {!selectedTemplate.is_builtin && (
                  <button
                    onClick={saveTemplate}
                    disabled={saving}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
                  >
                    {saving ? '保存中...' : '保存'}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
