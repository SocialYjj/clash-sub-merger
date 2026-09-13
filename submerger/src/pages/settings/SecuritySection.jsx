import React, { useState } from 'react';
import { Key, Eye, EyeOff } from 'lucide-react';

export default function SecuritySection({ onChangePassword }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!currentPassword.trim() || !newPassword.trim()) return;
    setSubmitting(true);
    try {
      const changed = await onChangePassword(currentPassword, newPassword);
      if (changed) {
        setCurrentPassword('');
        setNewPassword('');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="bg-gray-800/50 border border-gray-700/60 ring-1 ring-white/5 rounded-xl p-6 shadow-lg shadow-black/20">
      <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Key size={20} className="text-yellow-400" />
        安全设置
      </h2>

      <div className="space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-2">修改管理员密码</label>
          <div className="grid gap-2 md:grid-cols-[1fr_1fr_auto]">
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="输入当前密码"
                autoComplete="current-password"
                className="w-full px-3 py-2 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-sm"
              />
            </div>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="输入新密码"
                autoComplete="new-password"
                className="w-full px-3 py-2 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-sm"
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
              onClick={handleSubmit}
              disabled={!currentPassword.trim() || !newPassword.trim() || submitting}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50 text-sm font-medium"
            >
              {submitting ? '修改中...' : '修改'}
            </button>
          </div>
          <p className="text-xs text-gray-500 mt-1.5">密码要求：至少8个字符，建议包含字母、数字和符号组合</p>
        </div>
      </div>
    </div>
  );
}
