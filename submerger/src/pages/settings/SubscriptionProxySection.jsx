import { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import request, { isRequestCanceled } from '../../utils/request';

const API_BASE = '/api';
const shouldIgnoreRequest = (err, signal) => signal?.aborted || isRequestCanceled(err);

export default function SubscriptionProxySection({ showToast }) {
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
    <div className="bg-surface-2/50 border border-line/60 ring-1 ring-ink/5 rounded-xl p-6 shadow-lg shadow-black/20">
      <h2 className="text-lg font-semibold text-ink mb-4 flex items-center gap-2">
        <Shield size={20} className="text-blue-400" />
        订阅获取代理
      </h2>

      {loading ? (
        <div className="text-center py-4 text-ink-3 text-sm">加载中...</div>
      ) : (
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-ink-2 mb-2">代理地址</label>
            <input
              type="text"
              value={proxyUrl}
              onChange={(e) => setProxyUrl(e.target.value)}
              placeholder="socks5://warp:1080 或 http://proxy:8080"
              className="w-full px-3 py-2 bg-surface-3 border border-line-strong rounded-lg text-ink placeholder-ink-3 focus:outline-none focus:border-blue-500"
            />
            <p className="text-xs text-ink-3 mt-1">
              支持 socks5://、http:// 和 https://
            </p>
          </div>

          <div className="flex gap-3">
            <button
              onClick={saveSetting}
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-ink rounded-lg transition-colors disabled:opacity-50 text-sm font-medium"
            >
              {saving ? '保存中...' : '保存'}
            </button>
            {hasStoredProxy && (
              <button
                onClick={clearSetting}
                disabled={saving}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-ink rounded-lg transition-colors disabled:opacity-50 text-sm font-medium"
              >
                清除
              </button>
            )}
            <button
              onClick={testProxy}
              disabled={testing || !proxyUrl}
              className="px-4 py-2 bg-green-600 hover:bg-green-500 text-ink rounded-lg transition-colors disabled:opacity-50 text-sm font-medium"
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
}
