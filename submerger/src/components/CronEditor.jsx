import React, { useState, useEffect } from 'react';
import { Clock, Trash2 } from 'lucide-react';

export default function CronEditor({ value, onChange }) {
  const [cronInput, setCronInput] = useState(value || '');
  const [nextRun, setNextRun] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    setCronInput(value || '');
    if (value) {
      fetchNextRunTime(value);
    } else {
      setNextRun(null);
    }
  }, [value]);

  const fetchNextRunTime = async (cron) => {
    if (!cron || !cron.trim()) {
      setNextRun(null);
      setError('');
      return;
    }
    
    try {
      // Validate using backend
      const parts = cron.trim().split(/\s+/);
      if (parts.length !== 5) {
        setError('格式错误：需要5个字段 (分 时 日 月 周)');
        setNextRun(null);
        return;
      }
      
      // Simple frontend calculation for preview
      const [minute, hour] = parts;
      const now = new Date();
      let next = new Date(now);
      
      if (hour === '*' || hour.startsWith('*/')) {
        // Hourly pattern
        const interval = hour === '*' ? 1 : parseInt(hour.slice(2)) || 1;
        next.setMinutes(parseInt(minute) || 0);
        next.setSeconds(0);
        if (next <= now) {
          next.setHours(next.getHours() + interval);
        }
      } else if (!isNaN(parseInt(hour)) && !isNaN(parseInt(minute))) {
        // Daily at specific time
        next.setHours(parseInt(hour));
        next.setMinutes(parseInt(minute));
        next.setSeconds(0);
        if (next <= now) {
          next.setDate(next.getDate() + 1);
        }
      } else {
        setNextRun(null);
        setError('');
        return;
      }
      
      setNextRun(next);
      setError('');
    } catch (e) {
      setNextRun(null);
      setError('');
    }
  };

  const handleInputChange = (e) => {
    const newValue = e.target.value;
    setCronInput(newValue);
    
    // Live preview next run time as user types
    if (newValue.trim()) {
      fetchNextRunTime(newValue);
    } else {
      setNextRun(null);
      setError('');
    }
  };

  const handleBlur = () => {
    // Update parent on blur
    onChange(cronInput.trim() || null);
  };

  const handleClear = () => {
    setCronInput('');
    setNextRun(null);
    setError('');
    onChange(null);
  };

  return (
    <div className="space-y-3">
      {/* Current status */}
      <div className="flex items-center gap-2">
        <Clock size={16} className="text-gray-400" />
        <span className="text-sm text-gray-300">
          {value ? `已设置: ${value}` : '未设置定时更新'}
        </span>
      </div>

      {/* Cron input */}
      <div className="flex gap-2">
        <input
          type="text"
          value={cronInput}
          onChange={handleInputChange}
          onBlur={handleBlur}
          placeholder="分 时 日 月 周 (例: 0 */6 * * *)"
          className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        {cronInput && (
          <button
            type="button"
            onClick={handleClear}
            className="px-3 py-2 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded-lg transition-colors"
            title="清除"
          >
            <Trash2 size={16} />
          </button>
        )}
      </div>

      {/* Format hint */}
      <p className="text-xs text-gray-500">
        格式: 分钟(0-59) 小时(0-23) 日(1-31) 月(1-12) 周(0-6)
      </p>

      {/* Error message */}
      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}

      {/* Next run time */}
      {nextRun && !error && (
        <div className="text-xs text-green-400 bg-green-500/10 px-3 py-2 rounded-lg">
          下次执行: {nextRun.toLocaleString('zh-CN')}
        </div>
      )}

      {/* Common examples */}
      <div className="text-xs text-gray-500 space-y-1">
        <div className="font-medium text-gray-400">常用示例:</div>
        <div className="grid grid-cols-2 gap-1">
          <span><code className="text-cyan-400">0 */6 * * *</code> 每6小时</span>
          <span><code className="text-cyan-400">0 0 * * *</code> 每天凌晨</span>
          <span><code className="text-cyan-400">0 8 * * *</code> 每天早8点</span>
          <span><code className="text-cyan-400">0 */12 * * *</code> 每12小时</span>
        </div>
      </div>
    </div>
  );
}
