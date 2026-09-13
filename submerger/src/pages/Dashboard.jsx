import { useState, useEffect } from 'react';
import request from '../utils/request';
import {
  Server, Users, Router,
  Globe, Zap, Database
} from 'lucide-react';

const API_BASE = '/api';

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4'];

const COLOR_STYLES = {
  blue: {
    borderHover: 'hover:border-blue-500/50',
    glowBg: 'bg-blue-500/10 group-hover:bg-blue-500/20',
    iconBg: 'bg-blue-500/20 text-blue-400',
    subtext: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  },
  cyan: {
    borderHover: 'hover:border-cyan-500/50',
    glowBg: 'bg-cyan-500/10 group-hover:bg-cyan-500/20',
    iconBg: 'bg-cyan-500/20 text-cyan-400',
    subtext: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  },
  purple: {
    borderHover: 'hover:border-purple-500/50',
    glowBg: 'bg-purple-500/10 group-hover:bg-purple-500/20',
    iconBg: 'bg-purple-500/20 text-purple-400',
    subtext: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  },
  orange: {
    borderHover: 'hover:border-orange-500/50',
    glowBg: 'bg-orange-500/10 group-hover:bg-orange-500/20',
    iconBg: 'bg-orange-500/20 text-orange-400',
    subtext: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  },
};

const StatCard = ({ title, value, subtext, icon: Icon, color = 'blue', children }) => {
  const styles = COLOR_STYLES[color] || COLOR_STYLES.blue;
  return (
    <div className={`relative overflow-hidden rounded-2xl p-6 border border-gray-700/50 bg-gray-800/40 backdrop-blur-sm group ${styles.borderHover} ring-1 ring-white/5 transition-all duration-300 shadow-lg shadow-black/20 hover:shadow-black/40`}>
      <div className={`absolute -right-6 -top-6 w-32 h-32 ${styles.glowBg} rounded-full blur-3xl transition-all`} />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className={`p-3 rounded-xl ${styles.iconBg} group-hover:scale-110 transition-transform`}>
            <Icon size={24} />
          </div>
          {subtext && (
            <span className={`text-xs font-medium px-2 py-1 rounded-full border ${styles.subtext}`}>
              {subtext}
            </span>
          )}
        </div>

        <div className="space-y-1">
          <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
          <div className="text-3xl font-bold text-white tracking-tight">
            {value}
          </div>
          {children}
        </div>
      </div>
    </div>
  );
};

const DashboardSkeleton = () => (
  <div className="h-[calc(100vh-80px)] overflow-y-auto space-y-6 animate-pulse p-1">
    <div className="flex items-center justify-between mb-8">
      <div className="space-y-2">
        <div className="h-8 w-32 bg-gray-800 rounded-lg" />
        <div className="h-4 w-48 bg-gray-800/60 rounded" />
      </div>
      <div className="h-8 w-36 bg-gray-800/50 rounded-lg hidden sm:block" />
    </div>

    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {[1, 2, 3, 4].map((i) => (
        <div key={i} className="h-36 rounded-2xl border border-gray-800 bg-gray-800/30 p-6 space-y-4">
          <div className="flex justify-between items-center">
            <div className="w-12 h-12 rounded-xl bg-gray-700/40" />
            <div className="w-16 h-5 rounded-full bg-gray-700/30" />
          </div>
          <div className="space-y-2">
            <div className="h-3 w-16 bg-gray-700/30 rounded" />
            <div className="h-7 w-24 bg-gray-700/50 rounded" />
          </div>
        </div>
      ))}
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div className="h-80 rounded-2xl border border-gray-800 bg-gray-800/30 p-6 space-y-4">
        <div className="h-6 w-32 bg-gray-700/40 rounded" />
        <div className="space-y-3 pt-2">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="space-y-2">
              <div className="flex justify-between">
                <div className="h-4 w-20 bg-gray-700/30 rounded" />
                <div className="h-4 w-10 bg-gray-700/30 rounded" />
              </div>
              <div className="h-2 w-full bg-gray-700/20 rounded-full" />
            </div>
          ))}
        </div>
      </div>
      <div className="h-80 rounded-2xl border border-gray-800 bg-gray-800/30 p-6 space-y-4">
        <div className="h-6 w-32 bg-gray-700/40 rounded" />
        <div className="space-y-3 pt-2">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="space-y-2">
              <div className="flex justify-between">
                <div className="h-4 w-20 bg-gray-700/30 rounded" />
                <div className="h-4 w-10 bg-gray-700/30 rounded" />
              </div>
              <div className="h-2 w-full bg-gray-700/20 rounded-full" />
            </div>
          ))}
        </div>
      </div>
    </div>
  </div>
);

export default function Dashboard({ showToast }) {
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [overview, setOverview] = useState({
    subscriptions: { total: 0, active: 0 },
    nodes: { total: 0, by_protocol: {} },
    users: { total: 0, active: 0 },
    best_node: null
  });
  const [countryStats, setCountryStats] = useState([]);

  useEffect(() => {
    const controller = new AbortController();
    fetchData(controller.signal);
    return () => controller.abort();
  }, []);

  const fetchData = async (signal) => {
    setLoadError('');
    try {
      const [overviewRes, countryRes] = await Promise.all([
        request.get(`${API_BASE}/stats/overview`, { signal }),
        request.get(`${API_BASE}/stats/nodes-by-country`, { signal })
      ]);
      if (signal?.aborted) return;
      setOverview(overviewRes.data);
      setCountryStats(countryRes.data.countries || []);
    } catch (err) {
      if (signal?.aborted || err.name === 'CanceledError' || err.code === 'ERR_CANCELED') return;
      console.error('Failed to fetch dashboard data', err);
      const message = err.response?.data?.detail || err.message || '未知错误';
      setLoadError(`仪表盘数据加载失败: ${message}`);
      showToast?.(`仪表盘数据加载失败: ${message}`, 'error');
    } finally {
      if (!signal?.aborted) {
        setLoading(false);
      }
    }
  };

  // Process chart data
  const protocolData = Object.entries(overview.nodes.by_protocol || {})
    .map(([name, value]) => ({ name: name.toUpperCase(), value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6);

  const countryChartData = countryStats.slice(0, 10).map(c => ({
    name: c.name,
    code: c.code,
    flag: c.flag,
    value: c.count
  }));

  if (loading) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="h-[calc(100vh-80px)] overflow-y-auto space-y-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">仪表盘</h1>
          <p className="text-gray-400 text-sm">{loadError ? '部分数据加载失败' : '欢迎回来，系统运行正常'}</p>
        </div>
        <div className="text-right hidden sm:block">
          <div className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            SUB-MERGER
          </div>
        </div>
      </div>

      {loadError && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {loadError}
        </div>
      )}

      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="订阅总数"
          value={overview.subscriptions.total}
          subtext={`活跃: ${overview.subscriptions.active}`}
          icon={Database}
          color="blue"
        />
        <StatCard
          title="节点统计"
          value={overview.nodes.total}
          subtext="可用节点"
          icon={Server}
          color="cyan"
        />
        <StatCard
          title="用户总数"
          value={overview.users.total}
          subtext={`活跃: ${overview.users.active}`}
          icon={Users}
          color="purple"
        />
        <StatCard
          title="最低延迟"
          value={overview.best_node ? `${overview.best_node.latency} ms` : '--'}
          subtext="最优节点"
          icon={Zap}
          color="orange"
        >
          {overview.best_node ? (
            <p className="text-xs text-orange-400 truncate mt-2 font-medium" title={overview.best_node.name}>
              {overview.best_node.name}
            </p>
          ) : (
            <p className="text-xs text-gray-500 mt-2">暂无测速数据</p>
          )}
        </StatCard>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Country Distribution */}
        <div className="bg-gray-800/40 border border-gray-700/50 rounded-2xl p-6 backdrop-blur-sm ring-1 ring-white/5">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-blue-500/20 rounded-lg text-blue-400">
                <Globe size={18} />
              </div>
              <h3 className="text-lg font-bold text-white">节点地区分布</h3>
            </div>
            <span className="text-xs text-gray-500 bg-gray-700/50 px-2 py-1 rounded">Top 10</span>
          </div>

          <div className="space-y-4">
            {(() => {
              const totalNodes = countryChartData.reduce((sum, c) => sum + c.value, 0);
              if (totalNodes === 0) {
                return <div className="text-center py-8 text-gray-500 text-sm">暂无节点地区数据</div>;
              }
              return countryChartData.map((entry, index) => {
                const percentage = ((entry.value / totalNodes) * 100).toFixed(1);
                return (
                  <div key={index} className="group">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-2xl">{entry.flag}</span>
                        <span className="text-sm text-gray-300 font-medium">{entry.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-500">{percentage}%</span>
                        <span className="text-xs font-mono text-gray-500 bg-gray-800 px-2 py-1 rounded">
                          {entry.value}
                        </span>
                      </div>
                    </div>
                    <div className="h-2 bg-gray-700/50 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500 ease-out"
                        style={{
                          width: `${percentage}%`,
                          backgroundColor: COLORS[index % COLORS.length]
                        }}
                      />
                    </div>
                  </div>
                );
              });
            })()}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-gray-800/40 border border-gray-700/50 rounded-2xl p-6 backdrop-blur-sm ring-1 ring-white/5">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-green-500/20 rounded-lg text-green-400">
                <Router size={18} />
              </div>
              <h3 className="text-lg font-bold text-white">节点协议分布</h3>
            </div>
          </div>

          <div className="space-y-3">
            {protocolData.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-sm">暂无节点协议数据</div>
            ) : (
              protocolData.map((entry, index) => {
                const totalNodes = protocolData.reduce((sum, p) => sum + p.value, 0);
                const percentage = totalNodes ? ((entry.value / totalNodes) * 100).toFixed(1) : 0;
                return (
                  <div key={index} className="group">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-sm text-gray-300 font-medium">{entry.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-500">{percentage}%</span>
                        <span className="text-xs font-mono text-gray-500 bg-gray-800 px-2 py-1 rounded">
                          {entry.value}
                        </span>
                      </div>
                    </div>
                    <div className="h-2 bg-gray-700/50 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500 ease-out"
                        style={{
                          width: `${percentage}%`,
                          backgroundColor: COLORS[index % COLORS.length]
                        }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
