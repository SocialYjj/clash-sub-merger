import React from 'react';
import { CheckCircle, XCircle, Info, AlertTriangle } from 'lucide-react';

export default function Toast({ show, message, type = 'success' }) {
  if (!show) return null;

  const icons = {
    success: <CheckCircle size={20} className="text-green-400" />,
    error: <XCircle size={20} className="text-red-400" />,
    info: <Info size={20} className="text-blue-400" />,
    warning: <AlertTriangle size={20} className="text-yellow-400" />,
  };

  const bgColors = {
    success: 'bg-green-500/10 border-green-500/20',
    error: 'bg-red-500/10 border-red-500/20',
    info: 'bg-blue-500/10 border-blue-500/20',
    warning: 'bg-yellow-500/10 border-yellow-500/20',
  };

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 animate-fade-in">
      <div role={type === 'error' ? 'alert' : 'status'} aria-live="polite" className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${bgColors[type] || bgColors.info} backdrop-blur-sm`}>
        {icons[type] || icons.info}
        <span className="text-white text-sm">{message}</span>
      </div>
    </div>
  );
}
