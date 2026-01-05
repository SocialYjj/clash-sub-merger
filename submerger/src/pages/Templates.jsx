import React, { useState, useEffect, useRef } from 'react';
import { FileCode, Upload, Save, RotateCcw } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

export default function Templates({ showToast }) {
  const [templateContent, setTemplateContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    fetchTemplate();
  }, []);

  const fetchTemplate = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/template`);
      setTemplateContent(res.data.content || '');
    } catch (err) {
      // If no saved template, get default
      try {
        const res = await axios.get(`${API_BASE}/template/default`);
        setTemplateContent(res.data.content || '');
      } catch (e) {
        console.error('Failed to fetch template', e);
      }
    } finally {
      setLoading(false);
    }
  };

  const resetTemplate = async () => {
    setResetting(true);
    try {
      const res = await axios.get(`${API_BASE}/template/default`);
      setTemplateContent(res.data.content || '');
      showToast?.('模板已重置为默认值');
    } catch (err) {
      showToast?.('重置失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setResetting(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('current_template', templateContent);

    try {
      const res = await axios.post(`${API_BASE}/template/parse`, formData);
      setTemplateContent(res.data.content || '');
      showToast?.('模板文件已导入');
    } catch (err) {
      showToast?.('导入失败: ' + (err.response?.data?.detail || err.message), 'error');
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const saveTemplate = async () => {
    setSaving(true);
    try {
      await axios.post(`${API_BASE}/template/save`, { content: templateContent });
      showToast?.('模板已保存');
    } catch (err) {
      showToast?.('保存失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">模板管理</h1>
          <p className="text-gray-400 text-sm mt-1">编辑 Clash 配置模板</p>
        </div>
        <div className="flex gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".yaml,.yml"
            onChange={handleFileUpload}
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
          >
            <Upload size={18} />
            导入
          </button>
          <button
            onClick={resetTemplate}
            disabled={resetting}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <RotateCcw size={18} className={resetting ? 'animate-spin' : ''} />
            重置
          </button>
          <button
            onClick={saveTemplate}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <Save size={18} />
            {saving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>

      {/* Editor */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCode size={18} className="text-gray-400" />
            <span className="text-white font-medium">配置模板</span>
          </div>


        </div>
        <div className="p-4">
          {loading ? (
            <div className="h-96 flex items-center justify-center text-gray-500">
              加载中...
            </div>
          ) : (
            <textarea
              value={templateContent}
              onChange={(e) => setTemplateContent(e.target.value)}
              className="w-full h-96 px-4 py-3 bg-gray-900 border border-gray-700 rounded-lg text-gray-300 font-mono text-sm resize-none focus:outline-none focus:border-blue-500"
              placeholder="# Clash 配置模板..."
              spellCheck={false}
            />
          )}
        </div>
        <div className="px-4 py-3 border-t border-gray-700 text-xs text-gray-500">
          提示：模板中的 proxies 和 proxy-groups 部分会被自动替换为订阅节点
        </div>
      </div>
    </div>
  );
}
