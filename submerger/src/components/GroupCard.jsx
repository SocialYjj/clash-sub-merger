import React from 'react';
import { Edit2 } from 'lucide-react';

const GroupCard = ({ group, currentNodes, availableNodes, onEdit }) => {
  const getTypeColor = (type) => {
    const colors = {
      'select': 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      'url-test': 'bg-green-500/10 text-green-400 border-green-500/30',
      'fallback': 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
      'load-balance': 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    };
    return colors[type] || 'bg-gray-500/10 text-gray-400 border-gray-500/30';
  };

  return (
    <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700 hover:border-gray-600 transition-colors">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 flex-1 min-w-0">
          {group.icon && <span className="text-lg flex-shrink-0">{group.icon}</span>}
          <h3 className="text-white font-medium text-sm truncate">{group.name}</h3>
        </div>
        <span className={`px-2 py-0.5 rounded text-xs border flex-shrink-0 ${getTypeColor(group.type)}`}>
          {group.type}
        </span>
      </div>

      {/* Description */}
      {group.description && (
        <p className="text-gray-400 text-xs mb-2 line-clamp-1">{group.description}</p>
      )}

      {/* Node count and edit button */}
      <div className="flex items-center justify-between">
        <div className="text-xs text-gray-400">
          {group.editable ? (
            <span>
              {currentNodes.length > 0 ? (
                <>已选 <span className="text-white font-medium">{currentNodes.length}</span> 个</>
              ) : (
                <span className="text-yellow-400">未配置</span>
              )}
            </span>
          ) : (
            <span>
              {currentNodes.length > 0 ? (
                <>{currentNodes.length} 个固定</>
              ) : (
                <>固定配置</>
              )}
            </span>
          )}
        </div>

        {group.editable && (
          <button
            onClick={() => onEdit(group.name)}
            className="flex items-center gap-1 px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs transition-colors"
          >
            <Edit2 size={12} />
            <span>编辑</span>
          </button>
        )}
      </div>

      {/* Show first few nodes for non-editable groups */}
      {!group.editable && currentNodes.length > 0 && (
        <div className="mt-2 pt-2 border-t border-gray-700">
          <div className="flex flex-wrap gap-1">
            {currentNodes.slice(0, 3).map((node, idx) => (
              <span key={idx} className="px-1.5 py-0.5 bg-gray-700/50 text-gray-300 text-xs rounded truncate max-w-[120px]" title={node}>
                {node}
              </span>
            ))}
            {currentNodes.length > 3 && (
              <span className="px-1.5 py-0.5 text-gray-400 text-xs">
                +{currentNodes.length - 3}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default GroupCard;
