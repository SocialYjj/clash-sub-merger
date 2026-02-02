import React, { useState, useEffect } from 'react';
import { X, Save, Loader2, RotateCcw } from 'lucide-react';
import request from '../utils/request';
import GroupCard from './GroupCard';
import NodeSelector from './NodeSelector';

const UserConfigEditor = ({ user, onClose, onSave, showToast, isAdminToken = false }) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [templateId, setTemplateId] = useState('');
  const [templateName, setTemplateName] = useState('');
  const [groups, setGroups] = useState([]);
  const [groupConfig, setGroupConfig] = useState({});
  const [yamlPreview, setYamlPreview] = useState('');
  const [editingGroup, setEditingGroup] = useState(null);
  const [showResetConfirm, setShowResetConfirm] = useState(false);

  // Determine API base path based on whether this is an admin token or user
  const apiBasePath = isAdminToken ? `/api/admin-tokens/${user.id}` : `/api/users/${user.id}`;

  // Load user's or admin token's group configuration
  useEffect(() => {
    loadGroupConfig();
  }, [user.id]);

  // Update YAML preview when groupConfig changes (real-time)
  useEffect(() => {
    if (!loading && groups.length > 0) {
      generateYamlPreview();
    }
  }, [groupConfig, groups, loading]);

  const loadGroupConfig = async () => {
    try {
      setLoading(true);
      const response = await request.get(`${apiBasePath}/group-config`);
      const data = response.data;
      
      setTemplateId(data.template_id);
      setTemplateName(data.template_name);
      setGroups(data.groups);
      
      // Build initial groupConfig from current_nodes
      const initialConfig = {};
      data.groups.forEach(group => {
        if (group.editable && group.current_nodes.length > 0) {
          initialConfig[group.name] = group.current_nodes;
        }
      });
      setGroupConfig(initialConfig);
      
      setLoading(false);
    } catch (error) {
      console.error('Failed to load group config:', error);
      showToast('加载配置失败', 'error');
      setLoading(false);
    }
  };

  // Generate YAML preview on the frontend (real-time, no API call)
  const generateYamlPreview = () => {
    try {
      const proxyGroups = groups.map(group => {
        const groupName = group.name;
        const groupType = group.type;
        
        // Get nodes for this group
        let nodes;
        if (groupName in groupConfig && groupConfig[groupName]) {
          // User has configured this group
          nodes = groupConfig[groupName];
        } else {
          // Not configured - use available nodes (excluding DIRECT/REJECT)
          nodes = group.available_nodes.filter(n => n !== 'DIRECT' && n !== 'REJECT');
        }
        
        return {
          name: groupName,
          type: groupType,
          proxies: nodes
        };
      });
      
      // Convert to YAML format (simple string generation)
      let yaml = 'proxy-groups:\n';
      proxyGroups.forEach(group => {
        yaml += `  - name: ${group.name}\n`;
        yaml += `    type: ${group.type}\n`;
        yaml += `    proxies:\n`;
        group.proxies.forEach(proxy => {
          yaml += `      - ${proxy}\n`;
        });
      });
      
      setYamlPreview(yaml);
    } catch (error) {
      console.error('Failed to generate YAML preview:', error);
      setYamlPreview('# 生成预览失败');
    }
  };

  const updateYamlPreview = async () => {
    try {
      const response = await request.get(`/api/users/${user.id}/preview-yaml`);
      setYamlPreview(response.data.yaml);
    } catch (error) {
      console.error('Failed to update YAML preview:', error);
    }
  };

  const handleEditGroup = (groupName) => {
    const group = groups.find(g => g.name === groupName);
    if (group) {
      setEditingGroup(group);
    }
  };

  const handleNodeSelectionConfirm = (selectedNodes) => {
    if (editingGroup) {
      setGroupConfig(prev => ({
        ...prev,
        [editingGroup.name]: selectedNodes
      }));
      setEditingGroup(null);
    }
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      await request.put(`${apiBasePath}/group-config`, {
        group_config: groupConfig
      });
      showToast('配置保存成功', 'success');
      onSave();
      onClose();
    } catch (error) {
      console.error('Failed to save config:', error);
      showToast('保存配置失败', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    try {
      setSaving(true);
      await request.post(`${apiBasePath}/reset-group-config`);
      showToast('配置已重置', 'success');
      setShowResetConfirm(false);
      // Reload the config
      await loadGroupConfig();
    } catch (error) {
      console.error('Failed to reset config:', error);
      showToast('重置配置失败', 'error');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-gray-800 rounded-lg p-8">
          <Loader2 className="animate-spin text-blue-500" size={48} />
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />
      
      <div className="fixed inset-8 md:inset-16 lg:inset-20 bg-gray-900 rounded-lg shadow-2xl z-50 flex flex-col max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700 flex-shrink-0">
          <div>
            <h2 className="text-xl font-semibold text-white">
              配置编辑器 - {isAdminToken ? '管理员 Token' : '用户'}: {user.name}
            </h2>
            <p className="text-sm text-gray-400 mt-1">模板: {templateName}</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowResetConfirm(true)}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-600 text-white rounded transition-colors"
              title="重置所有组配置到默认状态"
            >
              <RotateCcw size={18} />
              <span>重置配置</span>
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white rounded transition-colors"
            >
              {saving ? (
                <>
                  <Loader2 className="animate-spin" size={18} />
                  <span>保存中...</span>
                </>
              ) : (
                <>
                  <Save size={18} />
                  <span>保存</span>
                </>
              )}
            </button>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <X size={24} />
            </button>
          </div>
        </div>

        {/* Main content */}
        <div className="flex-1 flex overflow-hidden min-h-0">
          {/* Left: YAML Preview */}
          <div className="w-1/2 border-r border-gray-700 flex flex-col min-h-0">
            <div className="p-3 border-b border-gray-700 flex-shrink-0">
              <h3 className="text-white font-medium text-sm">YAML 预览</h3>
              <p className="text-xs text-gray-400 mt-1">自动生成，只读</p>
            </div>
            <div className="flex-1 overflow-auto p-3">
              <pre className="text-xs text-gray-300 font-mono bg-gray-800/50 p-3 rounded whitespace-pre-wrap break-words">
                {yamlPreview || '加载中...'}
              </pre>
            </div>
          </div>

          {/* Right: Visual Editor */}
          <div className="w-1/2 flex flex-col min-h-0">
            <div className="p-3 border-b border-gray-700 flex-shrink-0">
              <h3 className="text-white font-medium text-sm">可视化编辑</h3>
              <p className="text-xs text-gray-400 mt-1">
                {groups.length > 0 ? `共 ${groups.length} 个分组` : '加载中...'}
              </p>
            </div>
            <div className="flex-1 overflow-auto p-3">
              {groups.length === 0 ? (
                <div className="text-center text-gray-400 py-8">
                  <p>没有可配置的分组</p>
                  <p className="text-xs mt-2">请检查模板配置</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {groups.map((group) => (
                    <GroupCard
                      key={group.name}
                      group={group}
                      currentNodes={groupConfig[group.name] || group.current_nodes}
                      availableNodes={group.available_nodes}
                      onEdit={handleEditGroup}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Reset Confirmation Modal */}
      {showResetConfirm && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60]">
          <div className="bg-gray-800 rounded-xl p-6 max-w-sm mx-4 border border-gray-700">
            <h3 className="text-lg font-bold text-white mb-3">确认重置配置</h3>
            <p className="text-gray-300 text-sm mb-2">
              重置后，所有分组将恢复到默认状态（包含所有可用节点）。
            </p>
            <p className="text-gray-400 text-xs mb-4">
              此操作无法撤销，但您可以重新配置。
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowResetConfirm(false)}
                disabled={saving}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                取消
              </button>
              <button
                onClick={handleReset}
                disabled={saving}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {saving && <Loader2 className="animate-spin" size={16} />}
                确认重置
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Node Selector Modal */}
      {editingGroup && (
        <NodeSelector
          groupName={editingGroup.name}
          availableNodes={editingGroup.available_nodes}
          selectedNodes={groupConfig[editingGroup.name] || editingGroup.current_nodes}
          onConfirm={handleNodeSelectionConfirm}
          onCancel={() => setEditingGroup(null)}
        />
      )}
    </>
  );
};

export default UserConfigEditor;
