import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { Plus, RefreshCw, Trash2, Settings, Copy, Check, Power, Plane, Database, Clock, Server, Link2, Cpu, ChevronRight, ChevronDown, ChevronUp, Upload, X, Edit2, FileEdit, Lock, Eye, EyeOff, Key, LogOut, GripVertical, QrCode, ExternalLink, Users, UserPlus, User, Calendar, ToggleLeft, ToggleRight } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { DndContext, closestCenter, KeyboardSensor, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { arrayMove, SortableContext, sortableKeyboardCoordinates, useSortable, rectSortingStrategy } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';

const API_BASE = '/api';

// 可排序卡片组件
function SortableCard({ id, children }) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    zIndex: isDragging ? 50 : 'auto',
    opacity: isDragging ? 0.8 : 1,
  };

  return (
    <div ref={setNodeRef} style={style} {...attributes}>
      {children(listeners, isDragging)}
    </div>
  );
}

// 配置 axios 拦截器
axios.interceptors.request.use(config => {
  const session = localStorage.getItem('session');
  if (session) {
    config.headers.Authorization = session;
  }
  return config;
});

axios.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      localStorage.removeItem('session');
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

function App() {
  // 认证状态
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [hasPassword, setHasPassword] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState('');
  const [subToken, setSubToken] = useState('');
  const [subFilename, setSubFilename] = useState('config.yaml');
  const [subName, setSubName] = useState('机场聚合');
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);

  const [subscriptions, setSubscriptions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [showCustomNodesModal, setShowCustomNodesModal] = useState(false);
  const [newSubName, setNewSubName] = useState('');
  const [newSubUrl, setNewSubUrl] = useState('');
  const [copied, setCopied] = useState(false);
  const [templateContent, setTemplateContent] = useState('');
  const [customNodes, setCustomNodes] = useState([]);
  const [newNodeLink, setNewNodeLink] = useState('');
  const [newNodeName, setNewNodeName] = useState('');
  const [showAddMenu, setShowAddMenu] = useState(false);
  const [selectedSub, setSelectedSub] = useState(null);
  const [subNodes, setSubNodes] = useState([]);
  const [loadingNodes, setLoadingNodes] = useState(false);
  const [showSubDetailModal, setShowSubDetailModal] = useState(false);
  const [editingNodeId, setEditingNodeId] = useState(null);
  const [editingNodeName, setEditingNodeName] = useState('');
  const [editingSubNodeIdx, setEditingSubNodeIdx] = useState(null);
  const [editingSubNodeName, setEditingSubNodeName] = useState('');
  const [editingSubInfo, setEditingSubInfo] = useState(false);
  const [editingSubName, setEditingSubName] = useState('');
  const [editingSubUrl, setEditingSubUrl] = useState('');
  const [showNodeEditModal, setShowNodeEditModal] = useState(false);
  const [editingNodeContent, setEditingNodeContent] = useState('');
  const [editingNodeIndex, setEditingNodeIndex] = useState(null);
  const [editingCustomNodeId, setEditingCustomNodeId] = useState(null);
  const [showCustomNodeEditModal, setShowCustomNodeEditModal] = useState(false);
  const [editingCustomNodeContent, setEditingCustomNodeContent] = useState('');
  const [cardList, setCardList] = useState([]);
  const [showSubModal, setShowSubModal] = useState(false);
  // User Management States
  const [showUserModal, setShowUserModal] = useState(false);
  const [users, setUsers] = useState([]);
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [newUserName, setNewUserName] = useState('');
  const [newUserExpire, setNewUserExpire] = useState('');
  const [editingUser, setEditingUser] = useState(null);
  const [showUserDetailModal, setShowUserDetailModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [availableNodes, setAvailableNodes] = useState({});
  const [userAllocations, setUserAllocations] = useState({});
  const [expandedSubs, setExpandedSubs] = useState({});
  // Toast notification state
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  // User editing state
  const [editingUserId, setEditingUserId] = useState(null);
  const [editingUserName, setEditingUserName] = useState('');
  const addMenuRef = useRef(null);
  const templateFileRef = useRef(null);

  // Toast helper function
  const showToast = (message, type = 'success') => {
    setToast({ show: true, message, type });
    setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 2000);
  };

  // 检查认证状态
  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const res = await axios.get(`${API_BASE}/auth/status`);
      setHasPassword(res.data.has_password);
      setSubToken(res.data.sub_token || '');
      setSubFilename(res.data.sub_filename || 'config.yaml');
      setSubName(res.data.sub_name || '机场聚合');
      
      // 检查本地 session
      const session = localStorage.getItem('session');
      if (session && res.data.has_password) {
        // 验证 session 是否有效
        try {
          await axios.get(`${API_BASE}/subscriptions`);
          setIsLoggedIn(true);
        } catch {
          localStorage.removeItem('session');
          setIsLoggedIn(false);
        }
      }
      // 没有密码时不自动进入，停留在设置密码界面
    } catch (err) {
      console.error('检查认证状态失败', err);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogin = async () => {
    if (!password.trim()) return;
    setAuthError('');
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, { password });
      localStorage.setItem('session', res.data.session);
      setIsLoggedIn(true);
      setPassword('');
    } catch (err) {
      setAuthError(err.response?.data?.detail || '登录失败');
    }
  };

  const handleSetup = async () => {
    if (!password.trim()) return;
    setAuthError('');
    try {
      const res = await axios.post(`${API_BASE}/auth/setup`, { password });
      localStorage.setItem('session', res.data.session);
      setSubToken(res.data.sub_token);
      setHasPassword(true);
      setIsLoggedIn(true);
      setPassword('');
    } catch (err) {
      setAuthError(err.response?.data?.detail || '设置失败');
    }
  };

  const handleLogout = async () => {
    try {
      await axios.post(`${API_BASE}/auth/logout`);
    } catch {}
    localStorage.removeItem('session');
    setIsLoggedIn(false);
  };

  const handleChangePassword = async () => {
    if (!newPassword.trim()) return;
    try {
      const res = await axios.post(`${API_BASE}/auth/change-password`, { password: newPassword });
      localStorage.setItem('session', res.data.session);
      setNewPassword('');
      showToast('密码修改成功');
    } catch (err) {
      showToast('修改失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleRegenerateToken = async () => {
    if (!window.confirm('重新生成 token 后，旧的订阅地址将失效，确定继续？')) return;
    try {
      const res = await axios.post(`${API_BASE}/auth/regenerate-token`);
      setSubToken(res.data.sub_token);
      showToast('订阅 token 已重新生成');
    } catch (err) {
      showToast('生成失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleUpdateFilename = async () => {
    if (!subFilename.trim()) return;
    try {
      const res = await axios.post(`${API_BASE}/auth/sub-filename`, { filename: subFilename.trim() });
      setSubFilename(res.data.sub_filename);
      showToast('文件名已更新');
    } catch (err) {
      showToast('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleUpdateSubName = async () => {
    if (!subName.trim()) return;
    try {
      const res = await axios.post(`${API_BASE}/auth/sub-name`, { name: subName.trim() });
      setSubName(res.data.sub_name);
      showToast('配置名称已更新');
    } catch (err) {
      showToast('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  // 点击外部关闭下拉菜单
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (addMenuRef.current && !addMenuRef.current.contains(e.target)) {
        setShowAddMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (isLoggedIn) {
      fetchSubscriptions();
      fetchDefaultTemplate();
      fetchCustomNodes();
      fetchSourceOrder();
    }
  }, [isLoggedIn]);

  const fetchSubscriptions = async () => {
    try {
      const res = await axios.get(`${API_BASE}/subscriptions`);
      setSubscriptions(res.data.subscriptions);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchDefaultTemplate = async () => {
    try {
      const res = await axios.get(`${API_BASE}/template/default`);
      setTemplateContent(res.data.content);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchCustomNodes = async () => {
    try {
      const res = await axios.get(`${API_BASE}/custom-nodes`);
      setCustomNodes(res.data.nodes);
    } catch (err) {
      console.error(err);
    }
  };

  const addCustomNode = async () => {
    if (!newNodeLink.trim()) return;
    setLoading(true);
    try {
      const payload = { link: newNodeLink.trim() };
      if (newNodeName.trim()) {
        payload.name = newNodeName.trim();
      }
      await axios.post(`${API_BASE}/custom-nodes`, payload);
      setNewNodeLink('');
      setNewNodeName('');
      fetchCustomNodes();
    } catch (err) {
      showToast('添加失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const deleteCustomNode = async (nodeId) => {
    try {
      await axios.delete(`${API_BASE}/custom-nodes/${nodeId}`);
      fetchCustomNodes();
    } catch (err) {
      showToast('删除失败', 'error');
    }
  };

  const updateCustomNodeName = async (nodeId) => {
    if (!editingNodeName.trim()) return;
    try {
      await axios.put(`${API_BASE}/custom-nodes/${nodeId}`, { name: editingNodeName.trim() });
      setEditingNodeId(null);
      setEditingNodeName('');
      fetchCustomNodes();
    } catch (err) {
      showToast('更新失败', 'error');
    }
  };

  const startEditNode = (node) => {
    setEditingNodeId(node.id);
    setEditingNodeName(node.name);
  };

  // 打开自建节点编辑弹窗
  const openCustomNodeEditModal = async (node) => {
    setEditingCustomNodeId(node.id);
    // 从 yaml 文件获取完整配置
    try {
      const res = await axios.get(`${API_BASE}/custom-nodes`);
      const nodes = res.data.nodes || [];
      const idx = nodes.findIndex(n => n.id === node.id);
      if (idx >= 0) {
        // 读取 yaml 中的完整配置
        const yamlRes = await axios.get(`${API_BASE}/subscriptions/custom_nodes/nodes`).catch(() => null);
        if (yamlRes && yamlRes.data.nodes && yamlRes.data.nodes[idx]) {
          const fullNode = yamlRes.data.nodes[idx];
          const yamlStr = Object.entries(fullNode)
            .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
            .join('\n');
          setEditingCustomNodeContent(yamlStr);
        } else {
          // 使用基本信息
          setEditingCustomNodeContent(`name: ${node.name}\ntype: ${node.type}\nserver: ${node.server}\nport: ${node.port}`);
        }
      }
    } catch {
      setEditingCustomNodeContent(`name: ${node.name}\ntype: ${node.type}\nserver: ${node.server}\nport: ${node.port}`);
    }
    setShowCustomNodeEditModal(true);
  };

  // 保存自建节点编辑
  const saveCustomNodeEdit = async () => {
    if (!editingCustomNodeId) return;
    try {
      const lines = editingCustomNodeContent.split('\n');
      const node = {};
      for (const line of lines) {
        const idx = line.indexOf(':');
        if (idx > 0) {
          const key = line.substring(0, idx).trim();
          let value = line.substring(idx + 1).trim();
          if (value.startsWith('{') || value.startsWith('[')) {
            try { value = JSON.parse(value); } catch {}
          } else if (value === 'true') {
            value = true;
          } else if (value === 'false') {
            value = false;
          } else if (!isNaN(value) && value !== '') {
            value = Number(value);
          }
          node[key] = value;
        }
      }
      
      await axios.put(`${API_BASE}/custom-nodes/${editingCustomNodeId}/full`, { node });
      setShowCustomNodeEditModal(false);
      setEditingCustomNodeContent('');
      setEditingCustomNodeId(null);
      fetchCustomNodes();
    } catch (err) {
      showToast('保存失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  // dnd-kit sensors
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );

  // 拖动状态 - 使用 ref 避免 useEffect 在拖动结束后立即重建 cardList
  const [isDragging, setIsDragging] = useState(false);
  const justDraggedRef = useRef(false);

  // 拖动开始
  const handleDragStart = () => {
    setIsDragging(true);
    justDraggedRef.current = false;
  };

  // 拖动结束处理
  const handleDragEnd = async (event) => {
    const { active, over } = event;
    
    console.log('拖动结束:', { active: active?.id, over: over?.id });
    
    if (over && active.id !== over.id) {
      const oldIndex = cardList.findIndex(item => item.id === active.id);
      const newIndex = cardList.findIndex(item => item.id === over.id);
      
      console.log('移动:', { oldIndex, newIndex });
      
      const newOrder = arrayMove(cardList, oldIndex, newIndex);
      
      // 构建排序 ID 列表
      const orderIds = newOrder.map(item => item.type === 'custom' ? 'custom_nodes' : item.data.id);
      
      console.log('新排序:', orderIds);
      
      // 标记刚刚完成拖动，防止 useEffect 重建 cardList
      justDraggedRef.current = true;
      
      // 直接更新 cardList 和 sourceOrder
      setCardList(newOrder);
      setSourceOrder(orderIds);
      setIsDragging(false);
      
      try {
        console.log('发送请求到:', `${API_BASE}/subscriptions/reorder`);
        const res = await axios.put(`${API_BASE}/subscriptions/reorder`, { order: orderIds });
        console.log('排序保存成功:', res.data);
        // 成功后重置标记
        setTimeout(() => { justDraggedRef.current = false; }, 100);
      } catch (err) {
        console.error('排序保存失败:', err.response?.status, err.response?.data, err.message);
        justDraggedRef.current = false;
        // 失败时重新获取服务器的排序
        fetchSourceOrder();
      }
    } else {
      setIsDragging(false);
    }
  };

  // 获取排序配置并构建卡片列表
  const [sourceOrder, setSourceOrder] = useState([]);
  
  const fetchSourceOrder = async () => {
    try {
      const res = await axios.get(`${API_BASE}/source-order`);
      setSourceOrder(res.data.order || []);
    } catch {
      setSourceOrder([]);
    }
  };

  // User Management Functions
  const fetchUsers = async () => {
    try {
      const res = await axios.get(`${API_BASE}/users`);
      setUsers(res.data.users || []);
    } catch (err) {
      console.error('Failed to fetch users', err);
    }
  };

  const fetchAvailableNodes = async () => {
    try {
      const res = await axios.get(`${API_BASE}/available-nodes`);
      setAvailableNodes(res.data.sources || {});
    } catch (err) {
      console.error('Failed to fetch available nodes', err);
    }
  };

  const createUser = async () => {
    if (!newUserName.trim()) return;
    setLoading(true);
    try {
      const expireTime = newUserExpire ? Math.floor(new Date(newUserExpire).getTime() / 1000) : 0;
      await axios.post(`${API_BASE}/users`, { name: newUserName.trim(), expire_time: expireTime });
      setNewUserName('');
      setNewUserExpire('');
      setShowAddUserModal(false);
      fetchUsers();
      showToast('用户创建成功');
    } catch (err) {
      showToast('创建失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const deleteUser = async (userId) => {
    if (!window.confirm('确定要删除这个用户吗？')) return;
    try {
      await axios.delete(`${API_BASE}/users/${userId}`);
      fetchUsers();
      showToast('用户已删除');
    } catch (err) {
      showToast('删除失败', 'error');
    }
  };

  const toggleUser = async (userId, currentEnabled) => {
    try {
      await axios.put(`${API_BASE}/users/${userId}`, { enabled: !currentEnabled });
      fetchUsers();
      showToast(currentEnabled ? '用户已禁用' : '用户已启用');
    } catch (err) {
      showToast('操作失败', 'error');
    }
  };

  const updateUserName = async (userId) => {
    if (!editingUserName.trim()) return;
    try {
      await axios.put(`${API_BASE}/users/${userId}`, { name: editingUserName.trim() });
      setEditingUserId(null);
      setEditingUserName('');
      fetchUsers();
      showToast('用户名已更新');
    } catch (err) {
      showToast('更新失败', 'error');
    }
  };

  const copyUserSubUrl = async (user) => {
    try {
      // Get full user info to get token
      const res = await axios.get(`${API_BASE}/users/${user.id}`);
      const url = `${window.location.origin}/sub?token=${res.data.user.token}`;
      navigator.clipboard.writeText(url);
      showToast('订阅地址已复制');
    } catch (err) {
      showToast('复制失败', 'error');
    }
  };

  const regenerateUserToken = async (userId) => {
    if (!window.confirm('重新生成 token 后，旧的订阅地址将失效，确定继续？')) return;
    try {
      const res = await axios.post(`${API_BASE}/users/${userId}/regenerate-token`);
      if (selectedUser && selectedUser.id === userId) {
        setSelectedUser({ ...selectedUser, token: res.data.token });
      }
      fetchUsers();
      showToast('Token 已重新生成');
    } catch (err) {
      showToast('生成失败', 'error');
    }
  };

  const openUserDetail = async (user) => {
    try {
      // Get full user info including token
      const userRes = await axios.get(`${API_BASE}/users/${user.id}`);
      setSelectedUser(userRes.data.user);
      
      // Get user allocations
      const allocRes = await axios.get(`${API_BASE}/users/${user.id}/allocations`);
      setUserAllocations(allocRes.data.allocations || {});
      
      // Get available nodes
      await fetchAvailableNodes();
      
      setExpandedSubs({});
      setShowUserDetailModal(true);
    } catch (err) {
      showToast('获取用户信息失败', 'error');
    }
  };

  const saveUserAllocations = async () => {
    if (!selectedUser) return;
    try {
      await axios.put(`${API_BASE}/users/${selectedUser.id}/allocations`, { subscriptions: userAllocations });
      showToast('分配已保存');
    } catch (err) {
      showToast('保存失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const toggleSubAllocation = (subId) => {
    setUserAllocations(prev => {
      const newAlloc = { ...prev };
      if (newAlloc[subId]) {
        delete newAlloc[subId];
      } else {
        newAlloc[subId] = ['*']; // Default to all nodes
      }
      return newAlloc;
    });
  };

  const toggleNodeAllocation = (subId, nodeName) => {
    setUserAllocations(prev => {
      const newAlloc = { ...prev };
      if (!newAlloc[subId]) {
        newAlloc[subId] = [nodeName];
      } else if (newAlloc[subId].includes('*')) {
        // Switch from all to specific
        const allNodes = availableNodes[subId]?.nodes || [];
        newAlloc[subId] = allNodes.filter(n => n !== nodeName);
      } else if (newAlloc[subId].includes(nodeName)) {
        newAlloc[subId] = newAlloc[subId].filter(n => n !== nodeName);
        if (newAlloc[subId].length === 0) {
          delete newAlloc[subId];
        }
      } else {
        newAlloc[subId] = [...newAlloc[subId], nodeName];
        // Check if all nodes selected
        const allNodes = availableNodes[subId]?.nodes || [];
        if (newAlloc[subId].length === allNodes.length) {
          newAlloc[subId] = ['*'];
        }
      }
      return newAlloc;
    });
  };

  const selectAllNodes = (subId) => {
    setUserAllocations(prev => ({ ...prev, [subId]: ['*'] }));
  };

  const deselectAllNodes = (subId) => {
    setUserAllocations(prev => {
      const newAlloc = { ...prev };
      delete newAlloc[subId];
      return newAlloc;
    });
  };

  const fetchAllData = async () => {
    await Promise.all([fetchSubscriptions(), fetchCustomNodes(), fetchSourceOrder()]);
  };

  // 根据排序配置构建卡片列表
  useEffect(() => {
    // 拖动时或刚刚完成拖动时不重建，避免状态冲突
    if (isDragging || justDraggedRef.current) return;
    
    const items = [];
    const addedIds = new Set();
    
    // 按保存的顺序添加
    for (const id of sourceOrder) {
      if (id === 'custom_nodes' && customNodes.length > 0 && !addedIds.has('custom_nodes')) {
        items.push({ type: 'custom', id: 'custom_nodes', data: { id: 'custom_nodes', nodes: customNodes } });
        addedIds.add('custom_nodes');
      } else {
        const sub = subscriptions.find(s => s.id === id);
        if (sub && !addedIds.has(sub.id)) {
          items.push({ type: 'subscription', id: sub.id, data: sub });
          addedIds.add(sub.id);
        }
      }
    }
    
    // 添加不在排序中的新项目
    subscriptions.forEach(sub => {
      if (!addedIds.has(sub.id)) {
        items.push({ type: 'subscription', id: sub.id, data: sub });
        addedIds.add(sub.id);
      }
    });
    
    if (customNodes.length > 0 && !addedIds.has('custom_nodes')) {
      items.push({ type: 'custom', id: 'custom_nodes', data: { id: 'custom_nodes', nodes: customNodes } });
    }
    
    setCardList(items);
  }, [subscriptions, customNodes, sourceOrder, isDragging]);

  // 订阅节点编辑/删除
  const updateSubNode = async (idx) => {
    if (!editingSubNodeName.trim() || !selectedSub) return;
    try {
      await axios.put(`${API_BASE}/subscriptions/${selectedSub.id}/nodes/${idx}`, { name: editingSubNodeName.trim() });
      setEditingSubNodeIdx(null);
      setEditingSubNodeName('');
      // 刷新节点列表
      const res = await axios.get(`${API_BASE}/subscriptions/${selectedSub.id}/nodes`);
      setSubNodes(res.data.nodes || []);
    } catch (err) {
      showToast('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const deleteSubNode = async (idx) => {
    if (!selectedSub) return;
    if (!window.confirm('确定要删除这个节点吗？')) return;
    try {
      await axios.delete(`${API_BASE}/subscriptions/${selectedSub.id}/nodes/${idx}`);
      // 刷新节点列表
      const res = await axios.get(`${API_BASE}/subscriptions/${selectedSub.id}/nodes`);
      setSubNodes(res.data.nodes || []);
      // 更新订阅信息
      fetchSubscriptions();
    } catch (err) {
      showToast('删除失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  // 打开节点编辑弹窗
  const openNodeEditModal = (node, idx) => {
    setEditingNodeIndex(idx);
    // 将节点对象转为 YAML 格式显示
    const yamlStr = Object.entries(node)
      .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
      .join('\n');
    setEditingNodeContent(yamlStr);
    setShowNodeEditModal(true);
  };

  // 保存节点编辑
  const saveNodeEdit = async () => {
    if (!selectedSub || editingNodeIndex === null) return;
    try {
      // 解析编辑的内容
      const lines = editingNodeContent.split('\n');
      const node = {};
      for (const line of lines) {
        const idx = line.indexOf(':');
        if (idx > 0) {
          const key = line.substring(0, idx).trim();
          let value = line.substring(idx + 1).trim();
          // 尝试解析 JSON 对象
          if (value.startsWith('{') || value.startsWith('[')) {
            try { value = JSON.parse(value); } catch {}
          } else if (value === 'true') {
            value = true;
          } else if (value === 'false') {
            value = false;
          } else if (!isNaN(value) && value !== '') {
            value = Number(value);
          }
          node[key] = value;
        }
      }
      
      await axios.put(`${API_BASE}/subscriptions/${selectedSub.id}/nodes/${editingNodeIndex}/full`, { node });
      setShowNodeEditModal(false);
      setEditingNodeContent('');
      setEditingNodeIndex(null);
      // 刷新节点列表
      const res = await axios.get(`${API_BASE}/subscriptions/${selectedSub.id}/nodes`);
      setSubNodes(res.data.nodes || []);
    } catch (err) {
      showToast('保存失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const addSubscription = async () => {
    if (!newSubName || !newSubUrl) return;
    setLoading(true);
    try {
      await axios.post(`${API_BASE}/subscriptions`, { name: newSubName, url: newSubUrl });
      setNewSubName('');
      setNewSubUrl('');
      setShowAddModal(false);
      fetchSubscriptions();
    } catch (err) {
      showToast('添加失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const deleteSubscription = async (id) => {
    if (!window.confirm('确定要删除这个订阅吗？')) return;
    try {
      await axios.delete(`${API_BASE}/subscriptions/${id}`);
      fetchSubscriptions();
    } catch (err) {
      showToast('删除失败', 'error');
    }
  };

  const toggleSubscription = async (id) => {
    try {
      await axios.put(`${API_BASE}/subscriptions/${id}/toggle`);
      fetchSubscriptions();
    } catch (err) {
      showToast('操作失败', 'error');
    }
  };

  const refreshSubscription = async (id) => {
    setLoading(true);
    try {
      await axios.post(`${API_BASE}/subscriptions/${id}/refresh`);
      fetchSubscriptions();
    } catch (err) {
      showToast('刷新失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const refreshAll = async () => {
    setLoading(true);
    try {
      await axios.post(`${API_BASE}/subscriptions/refresh-all`);
      fetchSubscriptions();
    } catch (err) {
      showToast('刷新失败', 'error');
    } finally {
      setLoading(false);
    }
  };

  const copySubUrl = (format = '') => {
    let url = subToken 
      ? `${window.location.origin}/sub?token=${subToken}`
      : `${window.location.origin}/sub`;
    if (format) {
      url += (subToken ? '&' : '?') + `format=${format}`;
    }
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // 打开订阅详情
  const openSubDetail = async (sub) => {
    setSelectedSub(sub);
    setEditingSubInfo(false);
    setEditingSubName(sub.name);
    setEditingSubUrl(sub.url);
    setShowSubDetailModal(true);
    setLoadingNodes(true);
    try {
      const res = await axios.get(`${API_BASE}/subscriptions/${sub.id}/nodes`);
      setSubNodes(res.data.nodes || []);
    } catch (err) {
      console.error(err);
      setSubNodes([]);
    } finally {
      setLoadingNodes(false);
    }
  };

  // 更新订阅信息（名称、URL）
  const updateSubInfo = async () => {
    if (!selectedSub) return;
    const updates = {};
    if (editingSubName.trim() && editingSubName !== selectedSub.name) {
      updates.name = editingSubName.trim();
    }
    if (editingSubUrl.trim() && editingSubUrl !== selectedSub.url) {
      updates.url = editingSubUrl.trim();
    }
    if (Object.keys(updates).length === 0) {
      setEditingSubInfo(false);
      return;
    }
    try {
      const res = await axios.put(`${API_BASE}/subscriptions/${selectedSub.id}`, updates);
      setSelectedSub(res.data.subscription);
      setEditingSubInfo(false);
      fetchSubscriptions();
      // 如果 URL 变了，重新加载节点
      if (updates.url) {
        setLoadingNodes(true);
        const nodesRes = await axios.get(`${API_BASE}/subscriptions/${selectedSub.id}/nodes`);
        setSubNodes(nodesRes.data.nodes || []);
        setLoadingNodes(false);
      }
    } catch (err) {
      showToast('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  // 上传模板文件
  const handleTemplateUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('current_template', templateContent);
    
    try {
      const res = await axios.post(`${API_BASE}/template/parse`, formData);
      setTemplateContent(res.data.content);
    } catch (err) {
      showToast('解析模板失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
    
    // 清空 input 以便重复上传同一文件
    e.target.value = '';
  };

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return '永久';
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString('zh-CN');
  };

  const getExpireStatus = (expire) => {
    if (!expire) return { text: '永久', color: 'text-green-400' };
    const now = Date.now() / 1000;
    const days = Math.floor((expire - now) / 86400);
    if (days < 0) return { text: '已过期', color: 'text-red-400' };
    if (days < 7) return { text: `${days}天后过期`, color: 'text-yellow-400' };
    if (days < 30) return { text: `${days}天后过期`, color: 'text-orange-400' };
    return { text: formatDate(expire), color: 'text-white/60' };
  };

  const getUsagePercent = (upload, download, total) => {
    if (!total) return 0;
    return Math.min(100, ((upload + download) / total) * 100);
  };

  // 统计
  const totalNodes = subscriptions.filter(s => s.enabled).reduce((sum, s) => sum + (s.node_count || 0), 0) + customNodes.length;
  const totalTraffic = subscriptions.filter(s => s.enabled).reduce((sum, s) => sum + (s.total || 0), 0);
  const usedTraffic = subscriptions.filter(s => s.enabled).reduce((sum, s) => sum + (s.upload || 0) + (s.download || 0), 0);

  // 加载中
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 mx-auto mb-4 animate-spin text-blue-400" />
          <p className="text-white/60">加载中...</p>
        </div>
      </div>
    );
  }

  // 登录/设置密码页面
  if (!isLoggedIn) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="glass-panel p-8 w-full max-w-sm space-y-6"
        >
          <div className="text-center">
            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center">
              <Lock className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-2xl font-bold">✈️ 机场管理</h1>
            <p className="text-white/40 text-sm mt-1">
              {hasPassword ? '请输入密码登录' : '首次使用，请设置密码'}
            </p>
          </div>

          <div className="space-y-4">
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (hasPassword ? handleLogin() : handleSetup())}
                placeholder={hasPassword ? '输入密码' : '设置密码'}
                className="glass-input w-full pr-10"
                autoFocus
              />
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white/60"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {authError && (
              <p className="text-red-400 text-sm text-center">{authError}</p>
            )}

            <button
              onClick={hasPassword ? handleLogin : handleSetup}
              disabled={!password.trim()}
              className="w-full glass-btn bg-blue-600 hover:bg-blue-500 py-3"
            >
              {hasPassword ? '登录' : '设置密码并进入'}
            </button>
          </div>

          {!hasPassword && (
            <p className="text-white/30 text-xs text-center">
              设置密码后，面板和订阅地址都将受到保护
            </p>
          )}
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 font-sans">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-400">
              ✈️ 机场管理
            </h1>
            <p className="text-white/40 text-sm mt-1">聚合订阅管理面板</p>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => { setShowUserModal(true); fetchUsers(); }} className="glass-btn flex items-center gap-2 text-sm">
              <Users className="w-4 h-4" /> 用户管理
            </button>
            <button onClick={() => setShowSettingsModal(true)} className="glass-btn flex items-center gap-2 text-sm">
              <Key className="w-4 h-4" /> 安全设置
            </button>
            <button onClick={() => setShowTemplateModal(true)} className="glass-btn flex items-center gap-2 text-sm">
              <Settings className="w-4 h-4" /> 模板配置
            </button>
            <button onClick={refreshAll} disabled={loading} className="glass-btn flex items-center gap-2 text-sm">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> 刷新全部
            </button>
            {/* 添加下拉菜单 */}
            <div className="relative" ref={addMenuRef}>
              <button 
                onClick={(e) => { e.stopPropagation(); setShowAddMenu(!showAddMenu); }} 
                className="glass-btn bg-blue-600 hover:bg-blue-500 flex items-center gap-2 text-sm"
              >
                <Plus className="w-4 h-4" /> 添加 <ChevronDown className={`w-3 h-3 transition-transform ${showAddMenu ? 'rotate-180' : ''}`} />
              </button>
              {showAddMenu && (
                <div className="absolute right-0 mt-2 w-40 bg-slate-800 border border-white/20 rounded-xl py-2 z-[100] shadow-2xl">
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowAddModal(true); setShowAddMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-sm hover:bg-white/10 flex items-center gap-2"
                  >
                    <Plane className="w-4 h-4 text-blue-400" /> 添加订阅
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowCustomNodesModal(true); setShowAddMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-sm hover:bg-white/10 flex items-center gap-2"
                  >
                    <Cpu className="w-4 h-4 text-cyan-400" /> 自建节点
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4">
          <div className="glass-panel p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/20"><Plane className="w-5 h-5 text-blue-400" /></div>
              <div>
                <div className="text-2xl font-bold">{subscriptions.length}</div>
                <div className="text-white/40 text-xs">订阅总数</div>
              </div>
            </div>
          </div>
          <div className="glass-panel p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/20"><Server className="w-5 h-5 text-green-400" /></div>
              <div>
                <div className="text-2xl font-bold">{totalNodes}</div>
                <div className="text-white/40 text-xs">节点总数</div>
              </div>
            </div>
          </div>
          <div className="glass-panel p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/20"><Database className="w-5 h-5 text-purple-400" /></div>
              <div>
                <div className="text-2xl font-bold">{formatBytes(usedTraffic)}</div>
                <div className="text-white/40 text-xs">已用流量</div>
              </div>
            </div>
          </div>
          <div className="glass-panel p-4 cursor-pointer hover:bg-white/10 transition-colors" onClick={() => setShowSubModal(true)}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/20">
                <Link2 className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <div className="text-sm font-mono text-white/80 truncate">/sub{subToken ? '?token=...' : ''}</div>
                <div className="text-white/40 text-xs">点击获取订阅</div>
              </div>
            </div>
          </div>
        </div>

        {/* Subscription Cards */}
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragStart={handleDragStart} onDragEnd={handleDragEnd}>
          <SortableContext items={cardList.map(item => item.id)} strategy={rectSortingStrategy}>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {cardList.map((item) => {
                if (item.type === 'custom') {
                  // 自建节点卡片
                  return (
                    <SortableCard key="custom_nodes" id="custom_nodes">
                      {(listeners, isDragging) => (
                        <div 
                          className={`glass-panel p-5 space-y-4 border border-cyan-500/30 hover:border-cyan-500/50 transition-colors cursor-pointer ${isDragging ? 'shadow-2xl scale-105' : ''}`}
                          onClick={() => setShowCustomNodesModal(true)}
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-3">
                              <div 
                                {...listeners}
                                className="cursor-grab active:cursor-grabbing p-1 -m-1 touch-none" 
                                onClick={e => e.stopPropagation()}
                              >
                                <GripVertical className="w-4 h-4 text-white/30 hover:text-white/60" />
                              </div>
                              <div className="w-2 h-2 rounded-full bg-cyan-400" />
                              <div>
                                <h3 className="font-semibold text-lg">自建节点</h3>
                                <p className="text-white/30 text-xs truncate max-w-[200px]">拖动排序 · 点击管理</p>
                              </div>
                            </div>
                            <div className="flex items-center gap-1">
                              <Cpu className="w-4 h-4 text-cyan-400" />
                            </div>
                          </div>

                          <div className="grid grid-cols-3 gap-3 text-center">
                            <div className="bg-white/5 rounded-lg p-2">
                              <div className="text-lg font-bold text-cyan-400">{customNodes.length}</div>
                              <div className="text-[10px] text-white/40">节点</div>
                            </div>
                            <div className="bg-white/5 rounded-lg p-2">
                              <div className="text-lg font-bold text-purple-400">-</div>
                              <div className="text-[10px] text-white/40">已用</div>
                            </div>
                            <div className="bg-white/5 rounded-lg p-2">
                              <div className="text-lg font-bold text-green-400">∞</div>
                              <div className="text-[10px] text-white/40">总量</div>
                            </div>
                          </div>

                          <div>
                            <div className="flex justify-between text-xs text-white/40 mb-1">
                              <span>自建节点</span>
                              <span>无限制</span>
                            </div>
                            <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                              <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-cyan-400" style={{ width: '100%' }} />
                            </div>
                          </div>

                          <div className="flex items-center justify-between text-xs">
                            <div className="flex items-center gap-1 text-white/40">
                              <Clock className="w-3 h-3" />
                              <span className="text-cyan-400">永久有效</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </SortableCard>
                  );
                } else {
                  // 订阅卡片
                  const sub = item.data;
                  const usage = getUsagePercent(sub.upload, sub.download, sub.total);
                  const expireStatus = getExpireStatus(sub.expire);
                  
                  return (
                    <SortableCard key={sub.id} id={sub.id}>
                      {(listeners, isDragging) => (
                        <div 
                          className={`glass-panel p-5 space-y-4 hover:border-blue-500/50 transition-colors cursor-pointer ${!sub.enabled ? 'opacity-50' : ''} ${isDragging ? 'shadow-2xl scale-105' : ''}`}
                          onClick={() => openSubDetail(sub)}
                        >
                          {/* Header */}
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-3">
                              <div 
                                {...listeners}
                                className="cursor-grab active:cursor-grabbing p-1 -m-1 touch-none" 
                                onClick={e => e.stopPropagation()}
                              >
                                <GripVertical className="w-4 h-4 text-white/30 hover:text-white/60" />
                              </div>
                              <div className={`w-2 h-2 rounded-full ${sub.enabled ? 'bg-green-400' : 'bg-gray-500'}`} />
                              <div>
                                <h3 className="font-semibold text-lg">{sub.name}</h3>
                                <p className="text-white/30 text-xs truncate max-w-[180px]" title={sub.url}>{sub.url}</p>
                              </div>
                            </div>
                            <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                              <button onClick={() => toggleSubscription(sub.id)} className="p-1.5 rounded hover:bg-white/10" title={sub.enabled ? '禁用' : '启用'}>
                                <Power className={`w-4 h-4 ${sub.enabled ? 'text-green-400' : 'text-gray-500'}`} />
                              </button>
                              <button onClick={() => refreshSubscription(sub.id)} className="p-1.5 rounded hover:bg-white/10" title="刷新">
                                <RefreshCw className="w-4 h-4 text-white/60" />
                              </button>
                              <button onClick={() => deleteSubscription(sub.id)} className="p-1.5 rounded hover:bg-white/10" title="删除">
                                <Trash2 className="w-4 h-4 text-red-400/60 hover:text-red-400" />
                              </button>
                            </div>
                          </div>

                          {/* Stats Grid */}
                          <div className="grid grid-cols-3 gap-3 text-center">
                            <div className="bg-white/5 rounded-lg p-2">
                              <div className="text-lg font-bold text-blue-400">{sub.node_count || 0}</div>
                              <div className="text-[10px] text-white/40">节点</div>
                            </div>
                            <div className="bg-white/5 rounded-lg p-2">
                              <div className="text-lg font-bold text-purple-400">{formatBytes(sub.upload + sub.download)}</div>
                              <div className="text-[10px] text-white/40">已用</div>
                            </div>
                            <div className="bg-white/5 rounded-lg p-2">
                              <div className="text-lg font-bold text-green-400">{formatBytes(sub.total)}</div>
                              <div className="text-[10px] text-white/40">总量</div>
                            </div>
                          </div>

                          {/* Progress Bar */}
                          <div>
                            <div className="flex justify-between text-xs text-white/40 mb-1">
                              <span>流量使用</span>
                              <span>{usage.toFixed(1)}%</span>
                            </div>
                            <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                              <div 
                                className={`h-full rounded-full transition-all ${usage > 90 ? 'bg-red-500' : usage > 70 ? 'bg-yellow-500' : 'bg-gradient-to-r from-blue-500 to-purple-500'}`}
                                style={{ width: `${usage}%` }}
                              />
                            </div>
                          </div>

                          {/* Footer */}
                          <div className="flex items-center justify-between text-xs">
                            <div className="flex items-center gap-1 text-white/40">
                              <Clock className="w-3 h-3" />
                              <span className={expireStatus.color}>{expireStatus.text}</span>
                            </div>
                            {sub.last_update && (
                              <span className="text-white/30">更新于 {new Date(sub.last_update * 1000).toLocaleString('zh-CN')}</span>
                            )}
                          </div>
                        </div>
                      )}
                    </SortableCard>
                  );
                }
              })}
            </div>
          </SortableContext>
        </DndContext>

        {cardList.length === 0 && (
          <div className="text-center py-20 text-white/30">
            <Plane className="w-12 h-12 mx-auto mb-4 opacity-30" />
            <p>还没有添加任何订阅</p>
            <p className="text-sm mt-1">点击右上角"添加订阅"开始</p>
          </div>
        )}

        {/* Add Modal */}
        <AnimatePresence>
          {showAddModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel p-6 w-full max-w-md space-y-4"
                onClick={e => e.stopPropagation()}
              >
                <h2 className="text-xl font-bold">添加订阅</h2>
                <div className="space-y-3">
                  <input
                    type="text"
                    value={newSubName}
                    onChange={e => setNewSubName(e.target.value)}
                    placeholder="订阅名称（如：机场A）"
                    className="glass-input w-full"
                  />
                  <input
                    type="text"
                    value={newSubUrl}
                    onChange={e => setNewSubUrl(e.target.value)}
                    placeholder="订阅地址 URL"
                    className="glass-input w-full"
                  />
                </div>
                <div className="flex justify-end gap-2">
                  <button onClick={() => setShowAddModal(false)} className="glass-btn">取消</button>
                  <button onClick={addSubscription} disabled={loading || !newSubName || !newSubUrl} className="glass-btn bg-blue-600 hover:bg-blue-500">
                    {loading ? '添加中...' : '添加'}
                  </button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Template Modal */}
        <AnimatePresence>
          {showTemplateModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-4xl h-[80vh] flex flex-col"
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <h2 className="text-xl font-bold">模板配置</h2>
                  <button onClick={() => setShowTemplateModal(false)} className="text-white/60 hover:text-white">✕</button>
                </div>
                <div className="flex-1 p-4 overflow-hidden">
                  <textarea
                    value={templateContent}
                    onChange={e => setTemplateContent(e.target.value)}
                    className="w-full h-full glass-input font-mono text-xs resize-none"
                    spellCheck="false"
                  />
                </div>
                <div className="p-4 border-t border-white/10 flex justify-between">
                  <div className="flex gap-2">
                    <button onClick={fetchDefaultTemplate} className="glass-btn text-sm">重置为默认</button>
                    <input
                      type="file"
                      ref={templateFileRef}
                      onChange={handleTemplateUpload}
                      accept=".yaml,.yml"
                      className="hidden"
                    />
                    <button 
                      onClick={() => templateFileRef.current?.click()} 
                      className="glass-btn text-sm flex items-center gap-2"
                    >
                      <Upload className="w-4 h-4" /> 上传模板
                    </button>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => setShowTemplateModal(false)} className="glass-btn text-sm">关闭</button>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Custom Nodes Modal */}
        <AnimatePresence>
          {showCustomNodesModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-2xl max-h-[80vh] flex flex-col"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center gap-3">
                    <Cpu className="w-5 h-5 text-cyan-400" />
                    <h2 className="text-xl font-bold">自建节点管理</h2>
                  </div>
                  <button onClick={() => setShowCustomNodesModal(false)} className="text-white/60 hover:text-white">✕</button>
                </div>
                
                {/* 添加节点 */}
                <div className="p-4 border-b border-white/10 space-y-3">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={newNodeLink}
                      onChange={e => setNewNodeLink(e.target.value)}
                      placeholder="输入节点链接（支持多种协议）"
                      className="glass-input flex-1 text-sm font-mono"
                    />
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={newNodeName}
                      onChange={e => setNewNodeName(e.target.value)}
                      placeholder="自定义名称（可选，留空使用链接中的名称）"
                      className="glass-input flex-1 text-sm"
                      onKeyDown={e => e.key === 'Enter' && addCustomNode()}
                    />
                    <button 
                      onClick={addCustomNode} 
                      disabled={loading || !newNodeLink.trim()}
                      className="glass-btn bg-cyan-600 hover:bg-cyan-500 px-4"
                    >
                      <Plus className="w-4 h-4" />
                    </button>
                  </div>
                  <p className="text-white/30 text-xs">支持 vless/vmess/ss/trojan/tuic/hysteria2 等格式</p>
                </div>

                {/* 节点列表 */}
                <div className="flex-1 overflow-y-auto p-4 space-y-2">
                  {customNodes.length === 0 ? (
                    <div className="text-center py-10 text-white/30">
                      <Cpu className="w-10 h-10 mx-auto mb-3 opacity-30" />
                      <p>还没有添加自建节点</p>
                    </div>
                  ) : (
                    customNodes.map(node => (
                      <div key={node.id} className="flex items-center justify-between p-3 bg-white/5 rounded-lg group">
                        <div className="flex-1 min-w-0">
                          {editingNodeId === node.id ? (
                            <div className="flex items-center gap-2">
                              <input
                                type="text"
                                value={editingNodeName}
                                onChange={e => setEditingNodeName(e.target.value)}
                                onKeyDown={e => {
                                  if (e.key === 'Enter') updateCustomNodeName(node.id);
                                  if (e.key === 'Escape') { setEditingNodeId(null); setEditingNodeName(''); }
                                }}
                                className="glass-input text-sm flex-1"
                                autoFocus
                              />
                              <button onClick={() => updateCustomNodeName(node.id)} className="p-1.5 rounded hover:bg-white/10">
                                <Check className="w-4 h-4 text-green-400" />
                              </button>
                              <button onClick={() => { setEditingNodeId(null); setEditingNodeName(''); }} className="p-1.5 rounded hover:bg-white/10">
                                <X className="w-4 h-4 text-white/60" />
                              </button>
                            </div>
                          ) : (
                            <>
                              <div className="flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                                <span className="font-medium truncate">{node.name}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded bg-white/10 text-white/50">{node.type}</span>
                              </div>
                              <div className="text-xs text-white/30 mt-1 truncate font-mono">
                                {node.server}:{node.port}
                              </div>
                            </>
                          )}
                        </div>
                        {editingNodeId !== node.id && (
                          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button 
                              onClick={() => startEditNode(node)}
                              className="p-2 rounded hover:bg-white/10"
                              title="重命名"
                            >
                              <Edit2 className="w-4 h-4 text-white/60" />
                            </button>
                            <button 
                              onClick={() => openCustomNodeEditModal(node)}
                              className="p-2 rounded hover:bg-white/10"
                              title="编辑配置"
                            >
                              <FileEdit className="w-4 h-4 text-blue-400" />
                            </button>
                            <button 
                              onClick={() => deleteCustomNode(node.id)}
                              className="p-2 rounded hover:bg-white/10"
                              title="删除"
                            >
                              <Trash2 className="w-4 h-4 text-red-400" />
                            </button>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>

                <div className="p-4 border-t border-white/10 flex justify-between items-center">
                  <span className="text-white/40 text-sm">共 {customNodes.length} 个节点</span>
                  <button onClick={() => setShowCustomNodesModal(false)} className="glass-btn text-sm">关闭</button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Subscription Detail Modal */}
        <AnimatePresence>
          {showSubDetailModal && selectedSub && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-2xl max-h-[80vh] flex flex-col"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <Plane className="w-5 h-5 text-blue-400 flex-shrink-0" />
                    {editingSubInfo ? (
                      <div className="flex-1 space-y-2">
                        <input
                          type="text"
                          value={editingSubName}
                          onChange={e => setEditingSubName(e.target.value)}
                          placeholder="订阅名称"
                          className="glass-input w-full text-sm"
                          autoFocus
                        />
                        <input
                          type="text"
                          value={editingSubUrl}
                          onChange={e => setEditingSubUrl(e.target.value)}
                          placeholder="订阅地址"
                          className="glass-input w-full text-xs font-mono"
                        />
                        <div className="flex gap-2">
                          <button onClick={updateSubInfo} className="glass-btn text-xs bg-blue-600 hover:bg-blue-500 px-3 py-1">
                            <Check className="w-3 h-3 mr-1 inline" />保存
                          </button>
                          <button onClick={() => { setEditingSubInfo(false); setEditingSubName(selectedSub.name); setEditingSubUrl(selectedSub.url); }} className="glass-btn text-xs px-3 py-1">
                            取消
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <h2 className="text-xl font-bold truncate">{selectedSub.name}</h2>
                          <button 
                            onClick={() => setEditingSubInfo(true)} 
                            className="p-1 rounded hover:bg-white/10 flex-shrink-0"
                            title="编辑订阅信息"
                          >
                            <Edit2 className="w-4 h-4 text-white/40 hover:text-white/60" />
                          </button>
                        </div>
                        <p className="text-white/30 text-xs truncate max-w-[400px]">{selectedSub.url}</p>
                      </div>
                    )}
                  </div>
                  <button onClick={() => setShowSubDetailModal(false)} className="text-white/60 hover:text-white flex-shrink-0 ml-2">✕</button>
                </div>
                
                {/* 订阅信息 */}
                <div className="p-4 border-b border-white/10">
                  <div className="grid grid-cols-4 gap-3 text-center">
                    <div className="bg-white/5 rounded-lg p-3">
                      <div className="text-lg font-bold text-blue-400">{selectedSub.node_count || 0}</div>
                      <div className="text-xs text-white/40">节点数</div>
                    </div>
                    <div className="bg-white/5 rounded-lg p-3">
                      <div className="text-lg font-bold text-purple-400">{formatBytes(selectedSub.upload + selectedSub.download)}</div>
                      <div className="text-xs text-white/40">已用流量</div>
                    </div>
                    <div className="bg-white/5 rounded-lg p-3">
                      <div className="text-lg font-bold text-green-400">{formatBytes(selectedSub.total)}</div>
                      <div className="text-xs text-white/40">总流量</div>
                    </div>
                    <div className="bg-white/5 rounded-lg p-3">
                      <div className={`text-lg font-bold ${getExpireStatus(selectedSub.expire).color}`}>
                        {getExpireStatus(selectedSub.expire).text}
                      </div>
                      <div className="text-xs text-white/40">到期时间</div>
                    </div>
                  </div>
                </div>

                {/* 节点列表 */}
                <div className="flex-1 overflow-y-auto p-4 space-y-2">
                  <div className="text-white/40 text-sm mb-2">节点列表</div>
                  {loadingNodes ? (
                    <div className="text-center py-10 text-white/30">
                      <RefreshCw className="w-8 h-8 mx-auto mb-3 animate-spin opacity-30" />
                      <p>加载中...</p>
                    </div>
                  ) : subNodes.length === 0 ? (
                    <div className="text-center py-10 text-white/30">
                      <Server className="w-10 h-10 mx-auto mb-3 opacity-30" />
                      <p>暂无节点</p>
                    </div>
                  ) : (
                    subNodes.map((node, idx) => (
                      <div key={idx} className="flex items-center p-3 bg-white/5 rounded-lg group">
                        <div className="flex-1 min-w-0">
                          {editingSubNodeIdx === idx ? (
                            <div className="flex items-center gap-2">
                              <input
                                type="text"
                                value={editingSubNodeName}
                                onChange={e => setEditingSubNodeName(e.target.value)}
                                onKeyDown={e => {
                                  if (e.key === 'Enter') updateSubNode(idx);
                                  if (e.key === 'Escape') { setEditingSubNodeIdx(null); setEditingSubNodeName(''); }
                                }}
                                className="glass-input text-sm flex-1"
                                autoFocus
                              />
                              <button onClick={() => updateSubNode(idx)} className="p-1.5 rounded hover:bg-white/10">
                                <Check className="w-4 h-4 text-green-400" />
                              </button>
                              <button onClick={() => { setEditingSubNodeIdx(null); setEditingSubNodeName(''); }} className="p-1.5 rounded hover:bg-white/10">
                                <X className="w-4 h-4 text-white/60" />
                              </button>
                            </div>
                          ) : (
                            <>
                              <div className="flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-blue-400" />
                                <span className="font-medium truncate">{node.name}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded bg-white/10 text-white/50">{node.type}</span>
                              </div>
                              <div className="text-xs text-white/30 mt-1 truncate font-mono">
                                {node.server}:{node.port}
                              </div>
                            </>
                          )}
                        </div>
                        {editingSubNodeIdx !== idx && (
                          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button 
                              onClick={() => { setEditingSubNodeIdx(idx); setEditingSubNodeName(node.name); }}
                              className="p-2 rounded hover:bg-white/10"
                              title="重命名"
                            >
                              <Edit2 className="w-4 h-4 text-white/60" />
                            </button>
                            <button 
                              onClick={() => openNodeEditModal(node, idx)}
                              className="p-2 rounded hover:bg-white/10"
                              title="编辑配置"
                            >
                              <FileEdit className="w-4 h-4 text-blue-400" />
                            </button>
                            <button 
                              onClick={() => deleteSubNode(idx)}
                              className="p-2 rounded hover:bg-white/10"
                              title="删除"
                            >
                              <Trash2 className="w-4 h-4 text-red-400" />
                            </button>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>

                <div className="p-4 border-t border-white/10 flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <span className="text-white/40 text-sm">共 {subNodes.length} 个节点</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => {
                        if (window.confirm('确定要删除这个订阅吗？')) {
                          deleteSubscription(selectedSub.id);
                          setShowSubDetailModal(false);
                        }
                      }} 
                      className="glass-btn text-sm text-red-400 hover:bg-red-500/20 flex items-center gap-1"
                    >
                      <Trash2 className="w-4 h-4" /> 删除订阅
                    </button>
                    <button onClick={() => setShowSubDetailModal(false)} className="glass-btn text-sm">关闭</button>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Node Edit Modal */}
        <AnimatePresence>
          {showNodeEditModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-2xl max-h-[80vh] flex flex-col"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center gap-3">
                    <FileEdit className="w-5 h-5 text-blue-400" />
                    <h2 className="text-xl font-bold">编辑节点配置</h2>
                  </div>
                  <button onClick={() => setShowNodeEditModal(false)} className="text-white/60 hover:text-white">✕</button>
                </div>
                
                <div className="flex-1 p-4 overflow-hidden">
                  <p className="text-white/40 text-xs mb-2">格式: key: value（每行一个字段，对象用 JSON 格式）</p>
                  <textarea
                    value={editingNodeContent}
                    onChange={e => setEditingNodeContent(e.target.value)}
                    className="w-full h-[300px] glass-input font-mono text-sm resize-none"
                    spellCheck="false"
                  />
                </div>

                <div className="p-4 border-t border-white/10 flex justify-end gap-2">
                  <button onClick={() => setShowNodeEditModal(false)} className="glass-btn text-sm">取消</button>
                  <button onClick={saveNodeEdit} className="glass-btn bg-blue-600 hover:bg-blue-500 text-sm">保存</button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Custom Node Edit Modal */}
        <AnimatePresence>
          {showCustomNodeEditModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-2xl max-h-[80vh] flex flex-col"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center gap-3">
                    <FileEdit className="w-5 h-5 text-cyan-400" />
                    <h2 className="text-xl font-bold">编辑自建节点配置</h2>
                  </div>
                  <button onClick={() => setShowCustomNodeEditModal(false)} className="text-white/60 hover:text-white">✕</button>
                </div>
                
                <div className="flex-1 p-4 overflow-hidden">
                  <p className="text-white/40 text-xs mb-2">格式: key: value（每行一个字段，对象用 JSON 格式）</p>
                  <textarea
                    value={editingCustomNodeContent}
                    onChange={e => setEditingCustomNodeContent(e.target.value)}
                    className="w-full h-[300px] glass-input font-mono text-sm resize-none"
                    spellCheck="false"
                  />
                </div>

                <div className="p-4 border-t border-white/10 flex justify-end gap-2">
                  <button onClick={() => setShowCustomNodeEditModal(false)} className="glass-btn text-sm">取消</button>
                  <button onClick={saveCustomNodeEdit} className="glass-btn bg-cyan-600 hover:bg-cyan-500 text-sm">保存</button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Subscription Modal - 订阅弹窗 */}
        <AnimatePresence>
          {showSubModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
              onClick={() => setShowSubModal(false)}
            >
              <motion.div
                initial={{ scale: 0.9, y: 20 }}
                animate={{ scale: 1, y: 0 }}
                exit={{ scale: 0.9, y: 20 }}
                className="glass-panel w-full max-w-sm overflow-hidden"
                onClick={e => e.stopPropagation()}
              >
                {/* 二维码区域 - 固定用 Base64 给手机扫 */}
                <div className="p-6 flex flex-col items-center border-b border-white/10">
                  <div className="bg-white p-3 rounded-xl mb-4">
                    <QRCodeSVG 
                      value={subToken ? `${window.location.origin}/sub?token=${subToken}&format=base64` : `${window.location.origin}/sub?format=base64`}
                      size={160}
                      level="M"
                    />
                  </div>
                  <p className="text-white/60 text-sm">扫描二维码订阅 (Base64)</p>
                </div>

                {/* 操作按钮 */}
                <div className="divide-y divide-white/10">
                  {/* 通用订阅 - 不带 format 参数，后端根据 User-Agent 自动判断 */}
                  <button
                    onClick={() => {
                      copySubUrl('');
                      setTimeout(() => setShowSubModal(false), 500);
                    }}
                    className="w-full px-6 py-4 flex items-center gap-4 hover:bg-white/5 transition-colors"
                  >
                    <div className="p-2 rounded-lg bg-slate-700">
                      {copied ? <Check className="w-5 h-5 text-green-400" /> : <Copy className="w-5 h-5 text-white/80" />}
                    </div>
                    <span className="text-base">{copied ? '已复制!' : '复制通用订阅'}</span>
                  </button>

                  {/* 导入到 Clash */}
                  <button
                    onClick={() => {
                      const subUrl = subToken 
                        ? `${window.location.origin}/sub?token=${subToken}`
                        : `${window.location.origin}/sub`;
                      const clashUrl = `clash://install-config?url=${encodeURIComponent(subUrl)}&name=${encodeURIComponent(subName)}`;
                      window.location.href = clashUrl;
                    }}
                    className="w-full px-6 py-4 flex items-center gap-4 hover:bg-white/5 transition-colors"
                  >
                    <div className="p-2 rounded-lg bg-blue-500/20">
                      <img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2360a5fa'%3E%3Cpath d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z'/%3E%3C/svg%3E" alt="Clash" className="w-5 h-5" />
                    </div>
                    <span className="text-base">导入到 Clash</span>
                  </button>
                </div>

                {/* 关闭按钮 */}
                <div className="p-4 border-t border-white/10">
                  <button
                    onClick={() => setShowSubModal(false)}
                    className="w-full py-3 text-center text-white/60 hover:text-white hover:bg-white/5 rounded-lg transition-colors"
                  >
                    关闭
                  </button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* User Management Modal */}
        <AnimatePresence>
          {showUserModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-2xl max-h-[80vh] flex flex-col"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center gap-3">
                    <Users className="w-5 h-5 text-green-400" />
                    <h2 className="text-xl font-bold">用户管理</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => setShowAddUserModal(true)} 
                      className="glass-btn text-sm bg-green-600 hover:bg-green-500 flex items-center gap-1"
                    >
                      <UserPlus className="w-4 h-4" /> 添加用户
                    </button>
                    <button onClick={() => setShowUserModal(false)} className="text-white/60 hover:text-white">✕</button>
                  </div>
                </div>
                
                <div className="flex-1 overflow-y-auto p-4 space-y-2">
                  {users.length === 0 ? (
                    <div className="text-center py-10 text-white/30">
                      <Users className="w-10 h-10 mx-auto mb-3 opacity-30" />
                      <p>还没有添加用户</p>
                      <p className="text-sm mt-1">点击"添加用户"创建子账户</p>
                    </div>
                  ) : (
                    users.map(user => {
                      const isExpired = user.expire_time > 0 && user.expire_time < Date.now() / 1000;
                      return (
                        <div 
                          key={user.id} 
                          className={`flex items-center justify-between p-4 bg-white/5 rounded-lg group cursor-pointer hover:bg-white/10 ${!user.enabled || isExpired ? 'opacity-60' : ''}`}
                          onClick={() => openUserDetail(user)}
                        >
                          <div className="flex items-center gap-3 flex-1 min-w-0">
                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${user.enabled && !isExpired ? 'bg-green-400' : 'bg-gray-500'}`} />
                            <div className="min-w-0 flex-1">
                              {editingUserId === user.id ? (
                                <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                                  <input
                                    type="text"
                                    value={editingUserName}
                                    onChange={e => setEditingUserName(e.target.value)}
                                    className="glass-input text-sm py-1 px-2 w-32"
                                    autoFocus
                                    onKeyDown={e => {
                                      if (e.key === 'Enter') updateUserName(user.id);
                                      if (e.key === 'Escape') { setEditingUserId(null); setEditingUserName(''); }
                                    }}
                                  />
                                  <button onClick={() => updateUserName(user.id)} className="text-green-400 hover:text-green-300">
                                    <Check className="w-4 h-4" />
                                  </button>
                                  <button onClick={() => { setEditingUserId(null); setEditingUserName(''); }} className="text-white/40 hover:text-white">
                                    <X className="w-4 h-4" />
                                  </button>
                                </div>
                              ) : (
                                <div className="font-medium truncate">{user.name}</div>
                              )}
                              <div className="text-xs text-white/40 font-mono truncate">
                                Token: {user.token}
                              </div>
                              <div className="text-xs text-white/30 mt-1">
                                {user.expire_time > 0 
                                  ? (isExpired ? '已过期' : `到期: ${new Date(user.expire_time * 1000).toLocaleDateString('zh-CN')}`)
                                  : '永久有效'
                                }
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                            <button 
                              onClick={() => { setEditingUserId(user.id); setEditingUserName(user.name); }}
                              className="p-2 rounded hover:bg-white/10"
                              title="修改名字"
                            >
                              <Edit2 className="w-4 h-4 text-blue-400" />
                            </button>
                            <button 
                              onClick={() => copyUserSubUrl(user)}
                              className="p-2 rounded hover:bg-white/10"
                              title="复制订阅地址"
                            >
                              <Copy className="w-4 h-4 text-cyan-400" />
                            </button>
                            <button 
                              onClick={() => toggleUser(user.id, user.enabled)}
                              className="p-2 rounded hover:bg-white/10"
                              title={user.enabled ? '禁用' : '启用'}
                            >
                              {user.enabled ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5 text-gray-500" />}
                            </button>
                            <button 
                              onClick={() => deleteUser(user.id)}
                              className="p-2 rounded hover:bg-white/10"
                              title="删除"
                            >
                              <Trash2 className="w-4 h-4 text-red-400" />
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                <div className="p-4 border-t border-white/10 flex justify-between items-center">
                  <span className="text-white/40 text-sm">共 {users.length} 个用户</span>
                  <button onClick={() => setShowUserModal(false)} className="glass-btn text-sm">关闭</button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Add User Modal */}
        <AnimatePresence>
          {showAddUserModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel p-6 w-full max-w-md space-y-4"
                onClick={e => e.stopPropagation()}
              >
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <UserPlus className="w-5 h-5 text-green-400" /> 添加用户
                </h2>
                <div className="space-y-3">
                  <div>
                    <label className="text-sm text-white/60 block mb-1">用户名称</label>
                    <input
                      type="text"
                      value={newUserName}
                      onChange={e => setNewUserName(e.target.value)}
                      placeholder="如：小明"
                      className="glass-input w-full"
                      autoFocus
                    />
                  </div>
                  <div>
                    <label className="text-sm text-white/60 block mb-1">到期时间（可选）</label>
                    <input
                      type="date"
                      value={newUserExpire}
                      onChange={e => setNewUserExpire(e.target.value)}
                      className="glass-input w-full"
                    />
                    <p className="text-white/30 text-xs mt-1">留空表示永久有效</p>
                  </div>
                </div>
                <div className="flex justify-end gap-2">
                  <button onClick={() => { setShowAddUserModal(false); setNewUserName(''); setNewUserExpire(''); }} className="glass-btn">取消</button>
                  <button onClick={createUser} disabled={loading || !newUserName.trim()} className="glass-btn bg-green-600 hover:bg-green-500">
                    {loading ? '创建中...' : '创建'}
                  </button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* User Detail Modal */}
        <AnimatePresence>
          {showUserDetailModal && selectedUser && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-3xl max-h-[85vh] flex flex-col"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center gap-3">
                    <User className="w-5 h-5 text-green-400" />
                    <div>
                      <h2 className="text-xl font-bold">{selectedUser.name}</h2>
                      <p className="text-white/40 text-xs">
                        {selectedUser.expire_time > 0 
                          ? `到期: ${new Date(selectedUser.expire_time * 1000).toLocaleDateString('zh-CN')}`
                          : '永久有效'
                        }
                      </p>
                    </div>
                  </div>
                  <button onClick={() => setShowUserDetailModal(false)} className="text-white/60 hover:text-white">✕</button>
                </div>
                
                {/* User Subscription Link */}
                <div className="p-4 border-b border-white/10 space-y-3">
                  <div className="flex items-center justify-between">
                    <label className="text-sm text-white/60">用户订阅链接</label>
                    <button
                      onClick={() => regenerateUserToken(selectedUser.id)}
                      className="text-xs text-yellow-400 hover:text-yellow-300"
                    >
                      <RefreshCw className="w-3 h-3 inline mr-1" />重新生成
                    </button>
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={`${window.location.origin}/sub?token=${selectedUser.token}`}
                      readOnly
                      className="glass-input flex-1 font-mono text-xs"
                    />
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(`${window.location.origin}/sub?token=${selectedUser.token}`);
                        showToast('已复制订阅链接');
                      }}
                      className="glass-btn px-3"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Node Allocation */}
                <div className="flex-1 overflow-y-auto p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-medium text-white/80">节点分配</h3>
                    <p className="text-xs text-white/40">勾选要分配给该用户的订阅和节点</p>
                  </div>
                  
                  <div className="space-y-2">
                    {Object.entries(availableNodes).map(([subId, subInfo]) => {
                      const isAllocated = !!userAllocations[subId];
                      const isAllNodes = userAllocations[subId]?.includes('*');
                      const allocatedCount = isAllNodes ? subInfo.nodes.length : (userAllocations[subId]?.length || 0);
                      const isExpanded = expandedSubs[subId];
                      
                      return (
                        <div key={subId} className="bg-white/5 rounded-lg overflow-hidden">
                          {/* Subscription Header */}
                          <div className="flex items-center justify-between p-3 hover:bg-white/5">
                            <div className="flex items-center gap-3 flex-1">
                              <input
                                type="checkbox"
                                checked={isAllocated}
                                onChange={() => toggleSubAllocation(subId)}
                                className="w-4 h-4 rounded border-white/30 bg-white/10 text-green-500 focus:ring-green-500"
                              />
                              <div 
                                className="flex-1 cursor-pointer"
                                onClick={() => setExpandedSubs(prev => ({ ...prev, [subId]: !prev[subId] }))}
                              >
                                <div className="flex items-center gap-2">
                                  <span className="font-medium">{subInfo.name}</span>
                                  <span className="text-xs px-2 py-0.5 rounded bg-white/10 text-white/50">
                                    {allocatedCount}/{subInfo.nodes.length} 节点
                                  </span>
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {isAllocated && (
                                <>
                                  <button
                                    onClick={() => selectAllNodes(subId)}
                                    className="text-xs text-blue-400 hover:text-blue-300 px-2"
                                  >
                                    全选
                                  </button>
                                  <button
                                    onClick={() => deselectAllNodes(subId)}
                                    className="text-xs text-red-400 hover:text-red-300 px-2"
                                  >
                                    清空
                                  </button>
                                </>
                              )}
                              <button
                                onClick={() => setExpandedSubs(prev => ({ ...prev, [subId]: !prev[subId] }))}
                                className="p-1 hover:bg-white/10 rounded"
                              >
                                {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                              </button>
                            </div>
                          </div>
                          
                          {/* Node List */}
                          {isExpanded && (
                            <div className="px-3 pb-3 pt-1 border-t border-white/5">
                              <div className="grid grid-cols-2 md:grid-cols-3 gap-1 max-h-48 overflow-y-auto">
                                {subInfo.nodes.map(nodeName => {
                                  const isNodeAllocated = isAllNodes || userAllocations[subId]?.includes(nodeName);
                                  return (
                                    <label 
                                      key={nodeName}
                                      className={`flex items-center gap-2 p-2 rounded text-xs cursor-pointer hover:bg-white/5 ${isNodeAllocated ? 'bg-green-500/10' : ''}`}
                                    >
                                      <input
                                        type="checkbox"
                                        checked={isNodeAllocated}
                                        onChange={() => toggleNodeAllocation(subId, nodeName)}
                                        className="w-3 h-3 rounded border-white/30 bg-white/10 text-green-500 focus:ring-green-500"
                                      />
                                      <span className="truncate" title={nodeName}>{nodeName}</span>
                                    </label>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="p-4 border-t border-white/10 flex justify-between items-center">
                  <div className="text-white/40 text-sm">
                    已分配 {Object.keys(userAllocations).length} 个订阅源
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => setShowUserDetailModal(false)} className="glass-btn text-sm">取消</button>
                    <button onClick={saveUserAllocations} className="glass-btn bg-green-600 hover:bg-green-500 text-sm">
                      保存分配
                    </button>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Settings Modal */}
        <AnimatePresence>
          {showSettingsModal && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            >
              <motion.div
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.9 }}
                className="glass-panel w-full max-w-md"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center gap-3">
                    <Key className="w-5 h-5 text-yellow-400" />
                    <h2 className="text-xl font-bold">安全设置</h2>
                  </div>
                  <button onClick={() => setShowSettingsModal(false)} className="text-white/60 hover:text-white">✕</button>
                </div>
                
                <div className="p-4 space-y-6">
                  {/* 订阅 Token */}
                  <div className="space-y-2">
                    <label className="text-sm text-white/60">订阅 Token</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={subToken}
                        readOnly
                        className="glass-input flex-1 font-mono text-sm"
                      />
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(subToken);
                          showToast('Token 已复制');
                        }}
                        className="glass-btn px-3"
                        title="复制"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </div>
                    <p className="text-white/30 text-xs">订阅地址: /sub?token={subToken ? subToken.substring(0, 8) + '...' : ''}</p>
                    <button
                      onClick={handleRegenerateToken}
                      className="glass-btn text-sm text-yellow-400 hover:bg-yellow-500/20"
                    >
                      <RefreshCw className="w-4 h-4 mr-2 inline" /> 重新生成 Token
                    </button>
                  </div>

                  {/* 订阅文件名 */}
                  <div className="space-y-2 pt-4 border-t border-white/10">
                    <label className="text-sm text-white/60">订阅文件名</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={subFilename}
                        onChange={e => setSubFilename(e.target.value)}
                        placeholder="config.yaml"
                        className="glass-input flex-1 text-sm"
                      />
                      <button
                        onClick={handleUpdateFilename}
                        className="glass-btn px-3 bg-blue-600 hover:bg-blue-500"
                      >
                        保存
                      </button>
                    </div>
                    <p className="text-white/30 text-xs">下载订阅时的文件名，如 myconfig.yaml</p>
                  </div>

                  {/* 配置名称 */}
                  <div className="space-y-2 pt-4 border-t border-white/10">
                    <label className="text-sm text-white/60">配置名称</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={subName}
                        onChange={e => setSubName(e.target.value)}
                        placeholder="机场聚合"
                        className="glass-input flex-1 text-sm"
                      />
                      <button
                        onClick={handleUpdateSubName}
                        className="glass-btn px-3 bg-blue-600 hover:bg-blue-500"
                      >
                        保存
                      </button>
                    </div>
                    <p className="text-white/30 text-xs">导入客户端后显示的配置名称</p>
                  </div>

                  {/* 修改密码 */}
                  <div className="space-y-2 pt-4 border-t border-white/10">
                    <label className="text-sm text-white/60">修改密码</label>
                    <div className="relative">
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        value={newPassword}
                        onChange={e => setNewPassword(e.target.value)}
                        placeholder="输入新密码"
                        className="glass-input w-full pr-10"
                      />
                      <button
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white/60"
                      >
                        {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <button
                      onClick={handleChangePassword}
                      disabled={!newPassword.trim()}
                      className="glass-btn text-sm bg-blue-600 hover:bg-blue-500"
                    >
                      确认修改
                    </button>
                  </div>

                  {/* 登出 */}
                  <div className="pt-4 border-t border-white/10">
                    <button
                      onClick={handleLogout}
                      className="glass-btn text-sm text-red-400 hover:bg-red-500/20 w-full flex items-center justify-center gap-2"
                    >
                      <LogOut className="w-4 h-4" /> 退出登录
                    </button>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

      </div>

      {/* Toast Notification - Fixed at bottom center */}
      <AnimatePresence>
        {toast.show && (
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 50 }}
            className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-[100] px-4 py-2 rounded-lg shadow-lg ${
              toast.type === 'error' ? 'bg-red-600' : 'bg-green-600'
            } text-white text-sm font-medium`}
          >
            {toast.message}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default App;
