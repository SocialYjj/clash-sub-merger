import React, { useState, useEffect, useRef, lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { Eye, EyeOff, Lock, X, Check } from 'lucide-react';
import request, { isRequestCanceled } from './utils/request';
import { copyToClipboard } from './utils/clipboard';

// Components (keep these as regular imports since they're small and used frequently)
import Layout from './components/Layout';
import Toast from './components/Toast';
import ConfirmModal from './components/ConfirmModal';
import ErrorBoundary from './components/ErrorBoundary';
import SocksExportModal from './components/SocksExportModal';

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
function LoginPage({ hasPassword, onLogin, statusError = false }) {
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
      await onLogin(password);
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
              {statusError ? '无法连接服务器' : (hasPassword ? '登录' : '管理员未初始化')}
            </h1>
            <p className="text-gray-400 mt-2">
              {statusError
                ? '认证状态检查失败，请确认服务正在运行后刷新页面'
                : (hasPassword ? '请输入密码以继续' : '请在 .env 中配置 INITIAL_ADMIN_PASSWORD，然后重启服务')}
            </p>
          </div>

          {hasPassword && !statusError && <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="输入密码"
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
              {loading ? '处理中...' : '登录'}
            </button>
          </form>}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  // Auth state
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [hasPassword, setHasPassword] = useState(false);
  const [authStatusError, setAuthStatusError] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  // Data state
  const [subscriptions, setSubscriptions] = useState([]);
  const [customNodes, setCustomNodes] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const dataRequestVersions = useRef({ subscriptions: 0, customNodes: 0, users: 0 });
  const mountedRef = useRef(true);

  // Toast state
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  const toastTimerRef = useRef(null);

  // Confirm modal state
  const [confirmModal, setConfirmModal] = useState({
    open: false,
    title: '',
    message: '',
    type: 'warning',
    onConfirm: null
  });

  // Format selector state for user subscription
  const [formatSelectorUser, setFormatSelectorUser] = useState(null);
  const [showUserSocksExportModal, setShowUserSocksExportModal] = useState(false);

  const showToast = (message, type = 'success') => {
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current);
    }
    setToast({ show: true, message, type });
    toastTimerRef.current = setTimeout(() => {
      setToast({ show: false, message: '', type: 'success' });
      toastTimerRef.current = null;
    }, 3000);
  };

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    const onSessionExpired = () => {
      setIsLoggedIn(false);
      showToast('登录状态已失效，请重新登录', 'error');
    };
    window.addEventListener('session-expired', onSessionExpired);
    return () => window.removeEventListener('session-expired', onSessionExpired);
  }, []);

  const showConfirm = (title, message, onConfirm, type = 'warning') => {
    setConfirmModal({ open: true, title, message, type, onConfirm });
  };

  const getErrorMessage = (err, fallback) => (
    err.response?.data?.detail || err.message || fallback
  );

  const closeConfirm = () => {
    setConfirmModal({ open: false, title: '', message: '', type: 'warning', onConfirm: null });
  };

  // Check auth status on mount
  useEffect(() => {
    const controller = new AbortController();
    checkAuthStatus(controller.signal);
    return () => controller.abort();
  }, []);

  // Fetch data when logged in
  useEffect(() => {
    if (!isLoggedIn) return;
    const controller = new AbortController();
    fetchAllData(controller.signal);
    return () => controller.abort();
  }, [isLoggedIn]);

  const checkAuthStatus = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/auth/status`, { signal });
      if (signal?.aborted) return;
      setHasPassword(res.data.has_password);
      setAuthStatusError(false);

      const session = localStorage.getItem('session');
      if (session && res.data.has_password) {
        try {
          await request.get(`${API_BASE}/subscriptions`, { signal });
          if (signal?.aborted) return;
          setIsLoggedIn(true);
        } catch (err) {
          if (signal?.aborted || isRequestCanceled(err)) return;
          if (err.response?.status === 401) {
            localStorage.removeItem('session');
          } else {
            setIsLoggedIn(true);
          }
        }
      }
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Auth check failed', err);
      setAuthStatusError(true);
    } finally {
      if (!signal?.aborted) {
        setAuthLoading(false);
      }
    }
  };

  const handleLogin = async (password) => {
    const res = await request.post(`${API_BASE}/auth/login`, { password });
    localStorage.setItem('session', res.data.session);
    setIsLoggedIn(true);
  };

  const handleLogout = async () => {
    try {
      await request.post(`${API_BASE}/auth/logout`);
    } catch { }
    localStorage.removeItem('session');
    setIsLoggedIn(false);
  };

  const fetchAllData = async (signal) => {
    await Promise.all([
      fetchSubscriptions(signal),
      fetchCustomNodes(signal),
      fetchUsers(signal),
    ]);
  };

  const fetchSubscriptions = async (signal) => {
    const requestVersion = ++dataRequestVersions.current.subscriptions;
    try {
      const res = await request.get(`${API_BASE}/subscriptions`, { signal });
      if (signal?.aborted || !mountedRef.current || requestVersion !== dataRequestVersions.current.subscriptions) return;
      setSubscriptions(res.data.subscriptions || []);
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch subscriptions', err);
      showToast(`订阅列表加载失败: ${getErrorMessage(err, '未知错误')}`, 'error');
    }
  };

  const fetchCustomNodes = async (signal) => {
    const requestVersion = ++dataRequestVersions.current.customNodes;
    try {
      const res = await request.get(`${API_BASE}/custom-nodes`, { signal });
      if (signal?.aborted || !mountedRef.current || requestVersion !== dataRequestVersions.current.customNodes) return;
      setCustomNodes(res.data.nodes || []);
      return true;
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch custom nodes', err);
      showToast(`自建节点加载失败: ${getErrorMessage(err, '未知错误')}`, 'error');
      return false;
    }
  };

  const fetchUsers = async (signal) => {
    const requestVersion = ++dataRequestVersions.current.users;
    try {
      const res = await request.get(`${API_BASE}/users`, { signal });
      if (signal?.aborted || !mountedRef.current || requestVersion !== dataRequestVersions.current.users) return;
      setUsers(res.data.users || []);
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch users', err);
      showToast(`用户列表加载失败: ${getErrorMessage(err, '未知错误')}`, 'error');
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
      throw err;
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
      await request.post(
        `${API_BASE}/subscriptions/${id}/refresh`,
        null,
        { timeout: 180000 }
      );
      await fetchSubscriptions();
      showToast('订阅已更新');
    } catch (err) {
      if (err.response?.status === 409) {
        showToast('该订阅正在更新，请等待当前更新完成后再试', 'info');
      } else {
        showToast('更新失败: ' + getErrorMessage(err, '未知错误'), 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  const refreshAllSubscriptions = async () => {
    setLoading(true);
    try {
      const response = await request.post(
        `${API_BASE}/subscriptions/refresh-all`,
        null,
        { timeout: 300000 }
      );
      await fetchSubscriptions();
      const {
        status,
        success_count: successCount,
        failure_count: failureCount,
        results = [],
      } = response.data;
      const failureDetails = results
        .filter(item => item.status === 'error')
        .map(item => `${item.name}: ${item.error}`)
        .join('；');
      if (status === 'success') {
        showToast(`全部 ${successCount} 个订阅已更新`);
      } else if (status === 'partial') {
        showToast(`更新完成：成功 ${successCount} 个，失败 ${failureCount} 个。${failureDetails}`, 'info');
      } else {
        showToast(`更新失败：${failureCount} 个订阅均未更新。${failureDetails}`, 'error');
      }
    } catch (err) {
      showToast('更新失败: ' + getErrorMessage(err, '未知错误'), 'error');
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
      throw err;
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
    setFormatSelectorUser(user);
  };

  const copyUserSubUrlWithFormat = async (user, format, socksOptions = null) => {
    try {
      const res = await request.get(`${API_BASE}/users/${user.id}`);
      let url = `${window.location.origin}/sub?token=${encodeURIComponent(res.data.user.token)}`;
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
      setFormatSelectorUser(null);
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

  const changePassword = async (currentPassword, newPassword) => {
    try {
      const res = await request.post(`${API_BASE}/auth/change-password`, {
        current_password: currentPassword,
        new_password: newPassword
      });
      if (res.data?.session) {
        localStorage.setItem('session', res.data.session);
      }
      showToast('密码修改成功');
      return true;
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
    return <LoginPage hasPassword={hasPassword} onLogin={handleLogin} statusError={authStatusError} />;
  }

  // Main app
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Layout onLogout={handleLogout}>
          <Suspense fallback={
            <div className="flex items-center justify-center h-screen">
              <div className="text-gray-400">加载中...</div>
            </div>
          }>
            <Routes>
              <Route path="/" element={
                <Dashboard subscriptions={subscriptions} customNodes={customNodes} showToast={showToast} />
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
      
      {/* Format Selector for User Subscription */}
      {formatSelectorUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={() => setFormatSelectorUser(null)}>
          <div className="bg-gray-800 rounded-xl p-6 w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-white">选择格式</h3>
              <button onClick={() => setFormatSelectorUser(null)} className="text-gray-400 hover:text-white">
                <X size={18} />
              </button>
            </div>
            <div className="space-y-2">
              <button
                onClick={() => copyUserSubUrlWithFormat(formatSelectorUser, 'v2ray')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">V2Ray</div>
                <div className="text-xs text-gray-400 mt-1">用于导入 v2rayN 的订阅格式</div>
              </button>
              <button
                onClick={() => copyUserSubUrlWithFormat(formatSelectorUser, 'clash')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">Clash</div>
                <div className="text-xs text-gray-400 mt-1">标准Clash配置格式</div>
              </button>
              <button
                onClick={() => copyUserSubUrlWithFormat(formatSelectorUser, 'singbox')}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">Sing-box</div>
                <div className="text-xs text-gray-400 mt-1">Sing-box JSON 配置格式</div>
              </button>
              <button
                onClick={() => setShowUserSocksExportModal(true)}
                className="w-full px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-left"
              >
                <div className="font-medium">SOCKS</div>
                <div className="text-xs text-gray-400 mt-1">所有节点自动分配端口</div>
              </button>
            </div>
          </div>
        </div>
      )}
      {showUserSocksExportModal && formatSelectorUser && (
        <SocksExportModal
          onClose={() => setShowUserSocksExportModal(false)}
          onConfirm={(options) => {
            copyUserSubUrlWithFormat(formatSelectorUser, 'socks', options);
            setShowUserSocksExportModal(false);
          }}
        />
      )}
      </BrowserRouter>
    </ErrorBoundary>
  );
}
