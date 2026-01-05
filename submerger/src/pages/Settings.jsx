import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Database, Key, Globe, Clock, Save, RefreshCw, Copy, Check, Eye, EyeOff, Download, AlertCircle, CheckCircle, ToggleLeft, ToggleRight } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

export default function Settings({ 
  subToken, 
  subFilename, 
  subName,
  onUpdateFilename,
  onUpdateSubName,
  onRegenerateToken,
  onChangePassword,
  showToast
}) {
  const [geoipStatus, setGeoipStatus] = useState(null);
  const [geoipVersion, setGeoipVersion] = useState(null);
  const [geoipLatest, setGeoipLatest] = useState(null);
  const [updateCheck, setUpdateCheck] = useState(null);
  const [geoipLoading, setGeoipLoading] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [autoUpdateEnabled, setAutoUpdateEnabled] = useState(false);
  const [speedtestConfig, setSpeedtestConfig] = useState({});
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [editFilename, setEditFilename] = useState(subFilename);
  const [editSubName, setEditSubName] = useState(subName);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetchGeoipStatus();
    fetchSpeedtestConfig();
    checkGeoipUpdate();
    fetchGeoipAutoUpdateSetting();
  }, []);

  useEffect(() => {
    setEditFilename(subFilename);
    setEditSubName(subName);
  }, [subFilename, subName]);

  const fetchGeoipStatus = async () => {
    try {
      const res = await axios.get(`${API_BASE}/geoip/status`);
      setGeoipStatus(res.data);
    } catch (err) {
      console.error('Failed to fetch GeoIP status', err);
    }
  };

  const checkGeoipUpdate = async () => {
    setCheckingUpdate(true);
    try {
      const res = await axios.get(`${API_BASE}/geoip/check-update`);
      setUpdateCheck(res.data);
      setGeoipVersion(res.data.local_version);
      setGeoipLatest(res.data.latest_version);
    } catch (err) {
      console.error('Failed to check GeoIP update', err);
    } finally {
      setCheckingUpdate(false);
    }
  };

  const fetchSpeedtestConfig = async () => {
    try {
      const res = await axios.get(`${API_BASE}/speedtest/config`);
      setSpeedtestConfig(res.data);
    } catch (err) {
      console.error('Failed to fetch speedtest config', err);
    }
  };

  const fetchGeoipAutoUpdateSetting = async () => {
    try {
      const res = await axios.get(`${API_BASE}/geoip/auto-update-setting`);
      setAutoUpdateEnabled(res.data.enabled);
    } catch (err) {
      console.error('Failed to fetch GeoIP auto-update setting', err);
    }
  };

  const toggleAutoUpdate = async () => {
    try {
      const newValue = !autoUpdateEnabled;
      await axios.post(`${API_BASE}/geoip/auto-update-setting`, { enabled: newValue });
      setAutoUpdateEnabled(newValue);
      showToast(newValue ? '已开启自动更新' : '已关闭自动更新');
    } catch (err) {
      showToast('设置失败', 'error');
    }
  };

  const updateGeoipDatabase = async (force = false) => {
    setGeoipLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/geoip/auto-update`, { force });
      if (res.data.success) {
        if (res.data.updated) {
          showToast('GeoIP 数据库更新成功');
        } else {
          showToast(res.data.message);
        }
        fetchGeoipStatus();
        checkGeoipUpdate();
      } else {
        showToast(res.data.message, 'error');
      }
    } catch (err) {
      showToast('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setGeoipLoading(false);
    }
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

      {/* Subscription Settings */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Globe size={20} />
          订阅设置
        </h2>
        
        <div className="space-y-4">
          {/* Sub URL */}
          <div>
            <label className="block text-sm text-gray-400 mb-2">订阅地址</label>
            <div className="flex gap-2">
              <input
                type="text"
                readOnly
                value={subToken ? `${window.location.origin}/sub?token=${subToken}` : '未设置'}
                className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-300 text-sm"
              />
              <button
                onClick={copySubUrl}
                className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                {copied ? <Check size={18} /> : <Copy size={18} />}
              </button>
            </div>
          </div>

          {/* Filename */}
          <div>
            <label className="block text-sm text-gray-400 mb-2">订阅文件名</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={editFilename}
                onChange={(e) => setEditFilename(e.target.value)}
                className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={() => onUpdateFilename(editFilename)}
                className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
              >
                <Save size={18} />
              </button>
            </div>
          </div>

          {/* Config Name */}
          <div>
            <label className="block text-sm text-gray-400 mb-2">配置名称（客户端显示）</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={editSubName}
                onChange={(e) => setEditSubName(e.target.value)}
                className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={() => onUpdateSubName(editSubName)}
                className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
              >
                <Save size={18} />
              </button>
            </div>
          </div>

          {/* Regenerate Token */}
          <div>
            <button
              onClick={onRegenerateToken}
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white rounded-lg transition-colors"
            >
              <Key size={18} />
              重新生成订阅 Token
            </button>
            <p className="text-xs text-gray-500 mt-1">重新生成后旧的订阅地址将失效</p>
          </div>
        </div>
      </div>

      {/* GeoIP Settings */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Database size={20} />
          GeoIP 数据库
        </h2>
        
        <div className="space-y-4">
          {/* Auto Update Toggle */}
          <div className="flex items-center justify-between bg-gray-700/50 rounded-lg p-4">
            <div>
              <div className="text-white font-medium">自动更新</div>
              <div className="text-xs text-gray-400 mt-1">每天自动检查并更新 GeoIP 数据库</div>
            </div>
            <button
              onClick={toggleAutoUpdate}
              className={`p-1 rounded-lg transition-colors ${autoUpdateEnabled ? 'text-green-400' : 'text-gray-500'}`}
            >
              {autoUpdateEnabled ? <ToggleRight size={32} /> : <ToggleLeft size={32} />}
            </button>
          </div>

          {/* Version Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Local Version */}
            <div className="bg-gray-700/50 rounded-lg p-4">
              <div className="text-sm text-gray-400 mb-2">本地版本</div>
              {geoipVersion?.exists ? (
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${geoipStatus?.loaded ? 'bg-green-400' : 'bg-red-400'}`}></span>
                    <span className="text-white font-medium">
                      {geoipVersion.estimated_version || '未知'}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500">
                    大小: {geoipVersion.size_mb} MB
                  </div>
                  <div className="text-xs text-gray-500">
                    更新: {geoipVersion.modified}
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-2 text-yellow-400">
                  <AlertCircle size={16} />
                  <span>未安装</span>
                </div>
              )}
            </div>

            {/* Latest Version */}
            <div className="bg-gray-700/50 rounded-lg p-4">
              <div className="text-sm text-gray-400 mb-2">最新版本</div>
              {checkingUpdate ? (
                <div className="flex items-center gap-2 text-gray-400">
                  <RefreshCw size={16} className="animate-spin" />
                  <span>检查中...</span>
                </div>
              ) : geoipLatest?.success ? (
                <div className="space-y-1">
                  <div className="text-white font-medium">
                    {geoipLatest.latest_version || '未知'}
                  </div>
                  {geoipLatest.published_at && (
                    <div className="text-xs text-gray-500">
                      发布: {new Date(geoipLatest.published_at).toLocaleDateString('zh-CN')}
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-red-400">
                  <AlertCircle size={16} />
                  <span className="text-sm">检查失败</span>
                </div>
              )}
            </div>
          </div>

          {/* Update Status */}
          {updateCheck && (
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${
              updateCheck.update_available === true 
                ? 'bg-blue-500/10 text-blue-400' 
                : updateCheck.update_available === false 
                  ? 'bg-green-500/10 text-green-400'
                  : 'bg-yellow-500/10 text-yellow-400'
            }`}>
              {updateCheck.update_available === true ? (
                <Download size={16} />
              ) : updateCheck.update_available === false ? (
                <CheckCircle size={16} />
              ) : (
                <AlertCircle size={16} />
              )}
              <span className="text-sm">{updateCheck.message}</span>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={checkGeoipUpdate}
              disabled={checkingUpdate}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <RefreshCw size={18} className={checkingUpdate ? 'animate-spin' : ''} />
              检查更新
            </button>
            
            <button
              onClick={() => updateGeoipDatabase(false)}
              disabled={geoipLoading}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <Download size={18} className={geoipLoading ? 'animate-spin' : ''} />
              {geoipLoading ? '更新中...' : '立即更新'}
            </button>

            <button
              onClick={() => updateGeoipDatabase(true)}
              disabled={geoipLoading}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <RefreshCw size={18} />
              强制更新
            </button>
          </div>

          <p className="text-xs text-gray-500">
            数据来源: P3TERX/GeoLite.mmdb (GitHub)，{autoUpdateEnabled ? '已开启自动更新' : '可手动检查更新'}
          </p>
        </div>
      </div>

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
          </div>
        </div>
      </div>
    </div>
  );
}
