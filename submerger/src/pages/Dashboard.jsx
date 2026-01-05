import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Server, Users, Activity, Router,
  Globe, Zap, Database
} from 'lucide-react';
import {
  PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';


const API_BASE = '/api';

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4'];

const StatCard = ({ title, value, subtext, icon: Icon, color, gradient }) => (
  <div className={`relative overflow-hidden rounded-2xl p-6 border border-gray-700/50 bg-gray-800/40 backdrop-blur-sm group hover:border-${color}-500/50 transition-all duration-300`}>
    <div className={`absolute -right-6 -top-6 w-32 h-32 bg-${color}-500/10 rounded-full blur-3xl group-hover:bg-${color}-500/20 transition-all`} />

    <div className="relative z-10">
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-xl bg-${color}-500/20 text-${color}-400 group-hover:scale-110 transition-transform`}>
          <Icon size={24} />
        </div>
        {subtext && (
          <span className={`text-xs font-medium px-2 py-1 rounded-full bg-${color}-500/10 text-${color}-400 border border-${color}-500/20`}>
            {subtext}
          </span>
        )}
      </div>

      <div className="space-y-1">
        <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
        <div className="text-3xl font-bold text-white tracking-tight">
          {value}
        </div>
      </div>
    </div>
  </div>
);

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [overview, setOverview] = useState({
    subscriptions: { total: 0, active: 0 },
    nodes: { total: 0, by_protocol: {} },
    users: { total: 0, active: 0 },
    best_node: null
  });
  const [countryStats, setCountryStats] = useState([]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [overviewRes, countryRes] = await Promise.all([
        axios.get(`${API_BASE}/stats/overview`),
        axios.get(`${API_BASE}/stats/nodes-by-country`)
      ]);
      setOverview(overviewRes.data);
      setCountryStats(countryRes.data.countries || []);
    } catch (err) {
      console.error('Failed to fetch dashboard data', err);
    } finally {
      setLoading(false);
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
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin text-blue-500"><Activity size={32} /></div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">仪表盘</h1>
          <p className="text-gray-400 text-sm">欢迎回来，系统运行正常</p>
        </div>
        <div className="text-right hidden sm:block">
          <div className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            SUB-MERGER
          </div>
        </div>
      </div>

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
        <div className="relative overflow-hidden rounded-2xl p-6 border border-gray-700/50 bg-gray-800/40 backdrop-blur-sm group hover:border-orange-500/50 transition-all duration-300">
          <div className="absolute -right-6 -top-6 w-32 h-32 bg-orange-500/10 rounded-full blur-3xl group-hover:bg-orange-500/20 transition-all" />

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 rounded-xl bg-orange-500/20 text-orange-400 group-hover:scale-110 transition-transform">
                <Zap size={24} />
              </div>
              <span className="text-xs font-medium px-2 py-1 rounded-full bg-orange-500/10 text-orange-400 border border-orange-500/20">
                最优节点
              </span>
            </div>

            <div className="space-y-1">
              <h3 className="text-gray-400 text-sm font-medium">最低延迟</h3>
              <div className="text-3xl font-bold text-white tracking-tight">
                {overview.best_node ? `${overview.best_node.latency} ms` : '--'}
              </div>
              {overview.best_node && (
                <p className="text-xs text-orange-400 truncate mt-2" title={overview.best_node.name}>
                  {overview.best_node.name.length > 20
                    ? overview.best_node.name.substring(0, 20) + '...'
                    : overview.best_node.name}
                </p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Country Distribution */}
        <div className="bg-gray-800/40 border border-gray-700/50 rounded-2xl p-6 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-blue-500/20 rounded-lg text-blue-400">
                <Globe size={18} />
              </div>
              <h3 className="text-lg font-bold text-white">节点国家分布</h3>
            </div>
            <span className="text-xs text-gray-500 bg-gray-700/50 px-2 py-1 rounded">Top 10</span>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={countryChartData} layout="vertical" margin={{ left: 10, right: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis
                  dataKey="name"
                  type="category"
                  width={80}
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <RechartsTooltip
                  contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#fff' }}
                  cursor={{ fill: '#374151', opacity: 0.2 }}
                />
                <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={16}>
                  {countryChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-gray-800/40 border border-gray-700/50 rounded-2xl p-6 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-green-500/20 rounded-lg text-green-400">
                <Router size={18} />
              </div>
              <h3 className="text-lg font-bold text-white">节点协议分布</h3>
            </div>
          </div>

          <div className="flex items-center">
            <div className="h-64 w-1/2">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} stroke="rgba(0,0,0,0)" />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#fff', borderRadius: '8px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="w-1/2 pl-4 space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
              {protocolData.map((entry, index) => (
                <div key={index} className="flex items-center justify-between p-2 rounded hover:bg-gray-700/30 transition-colors">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                    <span className="text-sm text-gray-300 font-medium">{entry.name}</span>
                  </div>
                  <span className="text-xs font-mono text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">
                    {entry.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>


    </div >
  );
}
