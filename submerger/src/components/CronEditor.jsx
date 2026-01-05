import React, { useState, useEffect } from 'react';
import { Clock, ChevronDown } from 'lucide-react';

// Common cron presets organized by category
const PRESET_CATEGORIES = [
  {
    label: '常用',
    presets: [
      { label: '每小时', value: '0 * * * *', description: '每小时的第0分钟' },
      { label: '每2小时', value: '0 */2 * * *', description: '每2小时执行一次' },
      { label: '每3小时', value: '0 */3 * * *', description: '每3小时执行一次' },
      { label: '每6小时', value: '0 */6 * * *', description: '每天4次' },
      { label: '每12小时', value: '0 */12 * * *', description: '每天2次' },
    ]
  },
  {
    label: '每天',
    presets: [
      { label: '每天凌晨', value: '0 0 * * *', description: '每天 00:00' },
      { label: '每天早6点', value: '0 6 * * *', description: '每天 06:00' },
      { label: '每天早8点', value: '0 8 * * *', description: '每天 08:00' },
      { label: '每天中午', value: '0 12 * * *', description: '每天 12:00' },
      { label: '每天晚6点', value: '0 18 * * *', description: '每天 18:00' },
      { label: '每天晚10点', value: '0 22 * * *', description: '每天 22:00' },
    ]
  },
  {
    label: '每周',
    presets: [
      { label: '每周一', value: '0 0 * * 1', description: '周一凌晨' },
      { label: '每周三', value: '0 0 * * 3', description: '周三凌晨' },
      { label: '每周五', value: '0 0 * * 5', description: '周五凌晨' },
      { label: '每周日', value: '0 0 * * 0', description: '周日凌晨' },
      { label: '工作日', value: '0 8 * * 1-5', description: '周一至周五早8点' },
    ]
  },
  {
    label: '每月',
    presets: [
      { label: '每月1号', value: '0 0 1 * *', description: '每月1号凌晨' },
      { label: '每月15号', value: '0 0 15 * *', description: '每月15号凌晨' },
      { label: '每月最后一天', value: '0 0 L * *', description: '每月最后一天' },
    ]
  }
];

// Flatten presets for lookup
const ALL_PRESETS = PRESET_CATEGORIES.flatMap(cat => cat.presets);

// Parse cron expression to human readable
function parseCronToText(cron) {
  if (!cron) return '未设置';
  
  const preset = ALL_PRESETS.find(p => p.value === cron);
  if (preset) return preset.label;
  
  const parts = cron.split(' ');
  if (parts.length !== 5) return cron;
  
  const [minute, hour, day, month, weekday] = parts;
  
  let text = '';
  
  // Simple parsing for common patterns
  if (minute === '0' && hour === '*') {
    text = '每小时';
  } else if (minute === '0' && hour.startsWith('*/')) {
    text = `每${hour.slice(2)}小时`;
  } else if (minute === '0' && hour !== '*' && day === '*' && month === '*' && weekday === '*') {
    text = `每天 ${hour}:00`;
  } else if (minute !== '*' && hour !== '*' && day === '*' && month === '*' && weekday === '*') {
    text = `每天 ${hour}:${minute.padStart(2, '0')}`;
  } else if (weekday !== '*' && day === '*') {
    const weekdays = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
    if (weekday.includes('-')) {
      text = `每${weekday === '1-5' ? '工作日' : weekday}`;
    } else {
      text = `每${weekdays[parseInt(weekday)] || weekday}`;
    }
    if (hour !== '*') text += ` ${hour}:${minute.padStart(2, '0')}`;
  } else {
    text = cron;
  }
  
  return text;
}

// Calculate next run time from cron expression
function getNextRunTime(cron) {
  if (!cron) return null;
  
  try {
    const parts = cron.split(' ');
    if (parts.length !== 5) return null;
    
    const [minute, hour, day, month, weekday] = parts;
    const now = new Date();
    let next = new Date(now);
    
    // Simple calculation for common patterns
    if (hour === '*' || hour.startsWith('*/')) {
      // Hourly or every N hours
      const interval = hour === '*' ? 1 : parseInt(hour.slice(2));
      next.setMinutes(parseInt(minute) || 0);
      next.setSeconds(0);
      if (next <= now) {
        next.setHours(next.getHours() + interval);
      }
    } else if (day === '*' && month === '*' && weekday === '*') {
      // Daily at specific time
      next.setHours(parseInt(hour) || 0);
      next.setMinutes(parseInt(minute) || 0);
      next.setSeconds(0);
      if (next <= now) {
        next.setDate(next.getDate() + 1);
      }
    } else {
      return null; // Complex pattern, skip calculation
    }
    
    return next;
  } catch {
    return null;
  }
}

export default function CronEditor({ value, onChange, onSave, disabled }) {
  const [showDropdown, setShowDropdown] = useState(false);
  const [customMode, setCustomMode] = useState(false);
  const [customValue, setCustomValue] = useState(value || '');
  const [activeCategory, setActiveCategory] = useState(0);
  
  useEffect(() => {
    setCustomValue(value || '');
    // Check if value matches a preset
    const isPreset = ALL_PRESETS.some(p => p.value === value);
    setCustomMode(!isPreset && !!value);
  }, [value]);

  const handlePresetSelect = (preset) => {
    onChange(preset.value);
    setShowDropdown(false);
    setCustomMode(false);
  };

  const handleCustomChange = (e) => {
    setCustomValue(e.target.value);
  };

  const handleCustomSave = () => {
    onChange(customValue);
    if (onSave) onSave(customValue);
  };

  const handleClear = () => {
    onChange(null);
    setCustomValue('');
    setCustomMode(false);
  };

  const nextRun = getNextRunTime(value);
  const displayText = parseCronToText(value);

  return (
    <div className="space-y-3">
      {/* Current value display */}
      <div className="flex items-center gap-2">
        <Clock size={16} className="text-gray-400" />
        <span className="text-sm text-gray-300">
          {value ? displayText : '未设置定时更新'}
        </span>
      </div>

      {/* Preset selector */}
      <div className="relative">
        <button
          type="button"
          onClick={() => setShowDropdown(!showDropdown)}
          disabled={disabled}
          className="w-full flex items-center justify-between px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm hover:border-gray-500 disabled:opacity-50"
        >
          <span>{value ? displayText : '选择更新频率'}</span>
          <ChevronDown size={16} className={`transition-transform ${showDropdown ? 'rotate-180' : ''}`} />
        </button>

        {showDropdown && (
          <div className="absolute z-10 w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg shadow-lg overflow-hidden">
            {/* Category tabs */}
            <div className="flex border-b border-gray-700 bg-gray-800/50">
              {PRESET_CATEGORIES.map((cat, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setActiveCategory(idx)}
                  className={`flex-1 px-2 py-2 text-xs font-medium transition-colors ${
                    activeCategory === idx 
                      ? 'text-blue-400 border-b-2 border-blue-400' 
                      : 'text-gray-400 hover:text-gray-300'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
            
            {/* Presets for active category */}
            <div className="max-h-48 overflow-y-auto">
              {PRESET_CATEGORIES[activeCategory].presets.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handlePresetSelect(preset)}
                  className={`w-full px-3 py-2 text-left text-sm hover:bg-gray-700 transition-colors ${
                    value === preset.value ? 'bg-blue-500/20 text-blue-400' : 'text-gray-300'
                  }`}
                >
                  <div className="flex justify-between items-center">
                    <span className="font-medium">{preset.label}</span>
                    <span className="text-xs text-gray-500">{preset.description}</span>
                  </div>
                </button>
              ))}
            </div>
            
            {/* Custom and clear options */}
            <div className="border-t border-gray-700">
              <button
                type="button"
                onClick={() => { setCustomMode(true); setShowDropdown(false); }}
                className="w-full px-3 py-2 text-left text-sm text-gray-400 hover:bg-gray-700"
              >
                自定义 Cron 表达式...
              </button>
              {value && (
                <button
                  type="button"
                  onClick={handleClear}
                  className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-gray-700 border-t border-gray-700"
                >
                  清除定时设置
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Custom cron input */}
      {customMode && (
        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={customValue}
              onChange={handleCustomChange}
              placeholder="分 时 日 月 周 (例: 0 */6 * * *)"
              className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <button
              type="button"
              onClick={handleCustomSave}
              className="px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg"
            >
              应用
            </button>
          </div>
          <p className="text-xs text-gray-500">
            格式: 分钟(0-59) 小时(0-23) 日(1-31) 月(1-12) 周(0-6, 0=周日)
          </p>
        </div>
      )}

      {/* Next run time */}
      {nextRun && (
        <div className="text-xs text-gray-500">
          下次执行: {nextRun.toLocaleString('zh-CN')}
        </div>
      )}
    </div>
  );
}
