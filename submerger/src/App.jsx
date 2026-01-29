import React, { useState, useEffect, lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Eye, EyeOff, Lock } from 'lucide-react';
import request from './utils/request';

// Components (keep these as regular imports since they're small and used frequently)
import Layout from './components/Layout';
import Toast from './components/Toast';
import ConfirmModal from './components/ConfirmModal';

// Lazy load pages for code splitting (reduces initial bundle size by ~800KB)
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Subscriptions = lazy(() => import('./pages/Subscriptions'));
const Nodes = lazy(() => import('./pages/Nodes'));
const NodeMap = lazy(() => import('./pages/NodeMap'));
const Users = lazy(() => import('./pages/Users'));
const Settings = lazy(() => import('./pages/Settings'));
const Templates = lazy(() => import('./pages/Templates'));

const API_BASE = '/api';

// Login Page Component
function LoginPage({ hasPassword, onLogin, onSetup }) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!password.trim()) return;

    setError('');
    setLoading(true);

    try {
      if (hasPassword) {
        await onLogin(password);
      } else {
        await onSetup(password);
      }
    } catch (err) {
      setError(err.response?.data?.detail || '操作失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-gray-900 rounded-2xl p-8 border border-gray-800">
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-blue-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
              <Lock size={32} className="text-blue-500" />
            </div>
            <h1 className="text-2xl font-bold text-white">
              {hasPassword ? '登录' : '设置密码'}
            </h1>
            <p className="text-gray-400 mt-2">
              {hasPassword ? '请输入密码以继续' : '首次使用，请设置管理密码'}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={hasPassword ? '输入密码' : '设置密码'}
                className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 pr-12"
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>

            {error && (
              <p className="text-red-400 text-sm">{error}</p>
            )}

            <button
              type="submit"
              disabled={!password.trim() || loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
            >
              {loading ? '处理中...' : (hasPassword ? '登录' : '设置密码')}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  // Auth state
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [hasPassword, setHasPassword] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [subToken, setSubToken] = useState('');
  const [subFilename, setSubFilename] = useState('config.yaml');
  const [subName, setSubName] = useState('机场聚合');

  // Data state
  const [subscriptions, setSubscriptions] = useState([]);
  const [customNodes, setCustomNodes] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);

  // Toast state
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });

  // Confirm modal state
  const [confirmModal, setConfirmModal] = useState({
    open: false,
    title: '',
    message: '',
    type: 'warning',
    onConfirm: null
  });

  const showToast = (message, type = 'success') => {
    setToast({ show: true, message, type });
    setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 3000);
  };

  const showConfirm = (title, message, onConfirm, type = 'warning') => {
    setConfirmModal({ open: true, title, message, type, onConfirm });
  };

  const closeConfirm = () => {
    setConfirmModal({ open: false, title: '', message: '', type: 'warning', onConfirm: null });
  };

  // Check auth status on mount
  useEffect(() => {
    checkAuthStatus();
  }, []);

  // Fetch data when logged in
  useEffect(() => {
    if (isLoggedIn) {
      fetchAllData();
    }
  }, [isLoggedIn]);

  const checkAuthStatus = async () => {
    try {
      const res = await request.get(`${API_BASE}/auth/status`);
      setHasPassword(res.data.has_password);
      setSubToken(res.data.sub_token || '');
      setSubFilename(res.data.sub_filename || 'config.yaml');
      setSubName(res.data.sub_name || '机场聚合');

      const session = localStorage.getItem('session');
      if (session && res.data.has_password) {
        try {
          await request.get(`${API_BASE}/subscriptions`);
          setIsLoggedIn(true);
        } catch {
          localStorage.removeItem('session');
        }
      }
    } catch (err) {
      console.error('Auth check failed', err);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogin = async (password) => {
    const res = await request.post(`${API_BASE}/auth/login`, { password });
    localStorage.setItem('session', res.data.session);
    setIsLoggedIn(true);
  };

  const handleSetup = async (password) => {
    const res = await request.post(`${API_BASE}/auth/setup`, { password });
    localStorage.setItem('session', res.data.session);
    setSubToken(res.data.sub_token);
    setHasPassword(true);
    setIsLoggedIn(true);
  };

  const handleLogout = async () => {
    try {
      await request.post(`${API_BASE}/auth/logout`);
    } catch { }
    localStorage.removeItem('session');
    setIsLoggedIn(false);
  };

  const fetchAllData = async () => {
    await Promise.all([
      fetchSubscriptions(),
      fetchCustomNodes(),
      fetchUsers(),
    ]);
  };

  const fetchSubscriptions = async () => {
    try {
      const res = await request.get(`${API_BASE}/subscriptions`);
      setSubscriptions(res.data.subscriptions || []);
    } catch (err) {
      console.error('Failed to fetch subscriptions', err);
    }
  };

  const fetchCustomNodes = async () => {
    try {
      const res = await request.get(`${API_BASE}/custom-nodes`);
      setCustomNodes(res.data.nodes || []);
    } catch (err) {
      console.error('Failed to fetch custom nodes', err);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await request.get(`${API_BASE}/users`);
      setUsers(res.data.users || []);
    } catch (err) {
      console.error('Failed to fetch users', err);
    }
  };

  // Subscription handlers
  const addSubscription = async (name, url) => {
    setLoading(true);
    try {
      await request.post(`${API_BASE}/subscriptions`, { name, url });
      await fetchSubscriptions();
      showToast('订阅添加成功');
    } catch (err) {
      showToast('添加失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const deleteSubscription = async (id) => {
    showConfirm('删除订阅', '确定要删除这个订阅吗？', async () => {
      try {
        await request.delete(`${API_BASE}/subscriptions/${id}`);
        await fetchSubscriptions();
        showToast('订阅已删除');
      } catch (err) {
        showToast('删除失败', 'error');
      }
    }, 'danger');
  };

  const refreshSubscription = async (id) => {
    setLoading(true);
    try {
      await request.post(`${API_BASE}/subscriptions/${id}/refresh`);
      await fetchSubscriptions();
      showToast('订阅已更新');
    } catch (err) {
      showToast('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const refreshAllSubscriptions = async () => {
    setLoading(true);
    try {
      await request.post(`${API_BASE}/subscriptions/refresh-all`);
      await fetchSubscriptions();
      showToast('全部订阅已更新');
    } catch (err) {
      showToast('更新失败', 'error');
    } finally {
      setLoading(false);
    }
  };

  const toggleSubscription = async (id) => {
    try {
      await request.put(`${API_BASE}/subscriptions/${id}/toggle`);
      await fetchSubscriptions();
    } catch (err) {
      showToast('操作失败', 'error');
    }
  };

  // User handlers
  const addUser = async (name, expireTime) => {
    setLoading(true);
    try {
      await request.post(`${API_BASE}/users`, { name, expire_time: expireTime });
      await fetchUsers();
      showToast('用户创建成功');
    } catch (err) {
      showToast('创建失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const deleteUser = async (id) => {
    showConfirm('删除用户', '确定要删除这个用户吗？', async () => {
      try {
        await request.delete(`${API_BASE}/users/${id}`);
        await fetchUsers();
        showToast('用户已删除');
      } catch (err) {
        showToast('删除失败', 'error');
      }
    }, 'danger');
  };

  const toggleUser = async (id, currentEnabled) => {
    try {
      await request.put(`${API_BASE}/users/${id}`, { enabled: !currentEnabled });
      await fetchUsers();
      showToast(currentEnabled ? '用户已禁用' : '用户已启用');
    } catch (err) {
      showToast('操作失败', 'error');
    }
  };

  const copyUserSubUrl = async (user) => {
    try {
      const res = await request.get(`${API_BASE}/users/${user.id}`);
      const url = `${window.location.origin}/sub?token=${res.data.user.token}`;
      navigator.clipboard.writeText(url);
      showToast('订阅地址已复制');
    } catch (err) {
      showToast('复制失败', 'error');
    }
  };

  const regenerateUserToken = async (id) => {
    showConfirm('重新生成 Token', '重新生成 token 后，旧的订阅地址将失效，确定继续？', async () => {
      try {
        await request.post(`${API_BASE}/users/${id}/regenerate-token`);
        await fetchUsers();
        showToast('Token 已重新生成');
      } catch (err) {
        showToast('生成失败', 'error');
      }
    }, 'warning');
  };

  // Settings handlers
  const updateFilename = async (filename) => {
    try {
      const res = await request.post(`${API_BASE}/auth/sub-filename`, { filename });
      setSubFilename(res.data.sub_filename);
      showToast('文件名已更新');
    } catch (err) {
      showToast('更新失败', 'error');
    }
  };

  const updateSubName = async (name) => {
    try {
      const res = await request.post(`${API_BASE}/auth/sub-name`, { name });
      setSubName(res.data.sub_name);
      showToast('配置名称已更新');
    } catch (err) {
      showToast('更新失败', 'error');
    }
  };

  const regenerateToken = async () => {
    showConfirm('重新生成订阅 Token', '重新生成 token 后，旧的订阅地址将失效，确定继续？', async () => {
      try {
        const res = await request.post(`${API_BASE}/auth/regenerate-token`);
        setSubToken(res.data.sub_token);
        showToast('订阅 token 已重新生成');
      } catch (err) {
        showToast('生成失败', 'error');
      }
    }, 'warning');
  };

  const changePassword = async (newPassword) => {
    try {
      await request.post(`${API_BASE}/auth/change-password`, { password: newPassword });
      showToast('密码修改成功，即将跳转到登录页');
      // Wait 1 second before logging out to let user see the success message
      setTimeout(() => {
        localStorage.removeItem('session');
        setIsLoggedIn(false);
        // Force page reload to ensure clean state
        window.location.reload();
      }, 1000);
    } catch (err) {
      showToast('修改失败: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  // Loading state
  if (authLoading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-gray-400">加载中...</div>
      </div>
    );
  }

  // Not logged in
  if (!isLoggedIn) {
    return <LoginPage hasPassword={hasPassword} onLogin={handleLogin} onSetup={handleSetup} />;
  }

  // Main app
  return (
    <BrowserRouter>
      <Layout>
        <Suspense fallback={
          <div className="flex items-center justify-center h-screen">
            <div className="text-gray-400">加载中...</div>
          </div>
        }>
          <Routes>
            <Route path="/" element={
              <Dashboard subscriptions={subscriptions} customNodes={customNodes} />
            } />
            <Route path="/subscriptions" element={
              <Subscriptions
                subscriptions={subscriptions}
                onAdd={addSubscription}
                onDelete={deleteSubscription}
                onRefresh={refreshSubscription}
                onRefreshAll={refreshAllSubscriptions}
                onRefreshList={fetchSubscriptions}
                onToggle={toggleSubscription}
                onOpenDetail={(sub) => {/* TODO: implement detail modal */ }}
                loading={loading}
                showToast={showToast}
              />
            } />
            <Route path="/nodes" element={
              <Nodes
                subscriptions={subscriptions}
                customNodes={customNodes}
                onRefreshCustomNodes={fetchCustomNodes}
                showToast={showToast}
              />
            } />
            <Route path="/map" element={<NodeMap />} />
            <Route path="/users" element={
              <Users
                users={users}
                onAdd={addUser}
                onDelete={deleteUser}
                onToggle={toggleUser}
                onCopyUrl={copyUserSubUrl}
                onRefreshUsers={fetchUsers}
                loading={loading}
                showToast={showToast}
              />
            } />
            <Route path="/settings" element={
              <Settings
                subToken={subToken}
                subFilename={subFilename}
                subName={subName}
                onUpdateFilename={updateFilename}
                onUpdateSubName={updateSubName}
                onRegenerateToken={regenerateToken}
                onChangePassword={changePassword}
                showToast={showToast}
              />
            } />
            <Route path="/templates" element={
              <Templates showToast={showToast} />
            } />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </Layout>
      <Toast show={toast.show} message={toast.message} type={toast.type} />
      <ConfirmModal
        isOpen={confirmModal.open}
        onClose={closeConfirm}
        onConfirm={confirmModal.onConfirm}
        title={confirmModal.title}
        message={confirmModal.message}
        type={confirmModal.type}
      />
    </BrowserRouter>
  );
}
