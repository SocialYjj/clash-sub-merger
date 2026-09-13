import { useState, useEffect, useRef } from 'react';
import request, { isRequestCanceled } from '../utils/request';
import { SkeletonHeader, SkeletonStatGrid, SkeletonPanel, SkeletonRows } from '../components/Skeleton';
import * as echarts from 'echarts';
import { useTheme } from '../utils/theme';
import {
  Server, Users, Router,
  Globe, Zap, Database, TrendingUp
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
    <div className={`relative overflow-hidden rounded-2xl p-6 border border-line/50 bg-surface-2/40 backdrop-blur-sm group ${styles.borderHover} ring-1 ring-ink/5 transition-all duration-300 shadow-lg shadow-black/20 hover:shadow-black/40`}>
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
          <h3 className="text-ink-2 text-sm font-medium">{title}</h3>
          <div className="text-3xl font-bold text-ink tracking-tight">
            {value}
          </div>
          {children}
        </div>
      </div>
    </div>
  );
};

// 节点趋势折线图：左轴为节点总数（面积线），存在测速数据时右轴叠加最低延迟。
// 主题配色沿用 NodeMap 的 isLight 模式，主题或数据变化时整体重设 option。
const NodeTrendChart = ({ history }) => {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);
  const isLight = useTheme() === 'light';

  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current);
    }
    const chart = chartInstance.current;

    const hasLatency = history.some((point) => point.min_latency_ms != null);
    // 轴/标签/分隔线颜色随主题切换；数据点强调色两种主题下均保持可读
    const trendTheme = isLight ? {
      axisLine: '#cbd5e1',      // slate-300
      label: '#64748b',         // slate-500
      splitLine: 'rgba(15, 23, 42, 0.08)',
      tooltipBg: 'rgba(255, 255, 255, 0.97)',
      tooltipText: '#0f172a',
      tooltipBorder: '#e2e8f0',
    } : {
      axisLine: '#334155',      // slate-700
      label: '#94a3b8',         // slate-400
      splitLine: 'rgba(148, 163, 184, 0.15)',
      tooltipBg: 'rgba(15, 23, 42, 0.95)',
      tooltipText: '#fff',
      tooltipBorder: '#334155',
    };

    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        backgroundColor: trendTheme.tooltipBg,
        borderColor: trendTheme.tooltipBorder,
        borderWidth: 1,
        textStyle: { color: trendTheme.tooltipText, fontSize: 12 },
      },
      legend: hasLatency ? {
        top: 0,
        right: 0,
        itemWidth: 14,
        itemHeight: 6,
        itemGap: 12,
        textStyle: { color: trendTheme.label, fontSize: 11 },
      } : undefined,
      grid: { left: 8, right: 8, top: hasLatency ? 32 : 16, bottom: 0, containLabel: true },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: history.map((point) => point.date),
        axisLine: { lineStyle: { color: trendTheme.axisLine } },
        axisTick: { show: false },
        axisLabel: { color: trendTheme.label, fontSize: 11 },
      },
      yAxis: [
        {
          type: 'value',
          minInterval: 1,
          splitLine: { lineStyle: { color: trendTheme.splitLine } },
          axisLabel: { color: trendTheme.label, fontSize: 11 },
        },
        ...(hasLatency ? [{
          type: 'value',
          splitLine: { show: false },
          axisLabel: { color: trendTheme.label, fontSize: 11, formatter: '{value} ms' },
        }] : []),
      ],
      series: [
        {
          name: '节点数',
          type: 'line',
          smooth: true,
          symbol: 'circle',
          symbolSize: 6,
          showSymbol: history.length <= 31,
          data: history.map((point) => point.total_nodes),
          itemStyle: { color: '#3b82f6' },
          lineStyle: { width: 2, color: '#3b82f6' },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: isLight ? 'rgba(59, 130, 246, 0.25)' : 'rgba(59, 130, 246, 0.35)' },
              { offset: 1, color: 'rgba(59, 130, 246, 0)' },
            ]),
          },
        },
        ...(hasLatency ? [{
          name: '最低延迟 (ms)',
          type: 'line',
          yAxisIndex: 1,
          smooth: true,
          connectNulls: true,
          symbol: 'circle',
          symbolSize: 5,
          showSymbol: history.length <= 31,
          data: history.map((point) => point.min_latency_ms),
          itemStyle: { color: '#f59e0b' },
          lineStyle: { width: 2, type: 'dashed', color: '#f59e0b' },
        }] : []),
      ],
    };

    chart.setOption(option, true);

    const handleResize = () => {
      chartInstance.current?.resize();
    };
    window.addEventListener('resize', handleResize);
    const resizeObserver = typeof ResizeObserver !== 'undefined' && chartRef.current
      ? new ResizeObserver(handleResize)
      : null;
    resizeObserver?.observe(chartRef.current);

    return () => {
      window.removeEventListener('resize', handleResize);
      resizeObserver?.disconnect();
    };
  }, [history, isLight]);

  // 卸载时销毁实例（与 NodeMap 一致的 init/dispose 生命周期）
  useEffect(() => {
    return () => {
      if (chartInstance.current) {
        chartInstance.current.dispose();
        chartInstance.current = null;
      }
    };
  }, []);

  return <div ref={chartRef} className="w-full min-w-0 h-64" />;
};

const DashboardSkeleton = () => (  <div className="h-[calc(100vh-80px)] overflow-y-auto space-y-6 animate-pulse p-1">
    <SkeletonHeader actionClassName="hidden sm:block" />
    <SkeletonStatGrid />
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <SkeletonPanel>
        <SkeletonRows rows={5} />
      </SkeletonPanel>
      <SkeletonPanel>
        <SkeletonRows rows={5} />
      </SkeletonPanel>
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
  const [statsHistory, setStatsHistory] = useState([]);

  useEffect(() => {
    const controller = new AbortController();
    fetchData(controller.signal);
    return () => controller.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps -- 挂载时拉取一次；fetchData 闭包仅引用稳定 setter，属有意的 mount-once 模式
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

    // 趋势历史独立拉取：失败不影响仪表盘主体，仅展示空状态
    try {
      const historyRes = await request.get(`${API_BASE}/stats/history`, { signal });
      if (signal?.aborted) return;
      setStatsHistory(Array.isArray(historyRes.data?.history) ? historyRes.data.history : []);
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch stats history', err);
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
          <h1 className="text-2xl font-bold text-ink mb-1">仪表盘</h1>
          <p className="text-ink-2 text-sm">{loadError ? '部分数据加载失败' : '欢迎回来，系统运行正常'}</p>
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
            <p className="text-xs text-ink-3 mt-2">暂无测速数据</p>
          )}
        </StatCard>
      </div>

      {/* Node Trend */}
      <div className="bg-surface-2/40 border border-line/50 rounded-2xl p-6 backdrop-blur-sm ring-1 ring-ink/5 overflow-hidden min-w-0">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-purple-500/20 rounded-lg text-purple-400">
              <TrendingUp size={18} />
            </div>
            <h3 className="text-lg font-bold text-ink">节点趋势</h3>
          </div>
          {statsHistory.length >= 2 && (
            <span className="text-xs text-ink-3 bg-surface-3/50 px-2 py-1 rounded">近 {statsHistory.length} 天</span>
          )}
        </div>

        {statsHistory.length < 2 ? (
          <div className="text-center py-8 text-ink-3 text-sm">暂无数据</div>
        ) : (
          <NodeTrendChart history={statsHistory} />
        )}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Country Distribution */}
        <div className="bg-surface-2/40 border border-line/50 rounded-2xl p-6 backdrop-blur-sm ring-1 ring-ink/5">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-blue-500/20 rounded-lg text-blue-400">
                <Globe size={18} />
              </div>
              <h3 className="text-lg font-bold text-ink">节点地区分布</h3>
            </div>
            <span className="text-xs text-ink-3 bg-surface-3/50 px-2 py-1 rounded">Top 10</span>
          </div>

          <div className="space-y-4">
            {(() => {
              const totalNodes = countryChartData.reduce((sum, c) => sum + c.value, 0);
              if (totalNodes === 0) {
                return <div className="text-center py-8 text-ink-3 text-sm">暂无节点地区数据</div>;
              }
              return countryChartData.map((entry, index) => {
                const percentage = ((entry.value / totalNodes) * 100).toFixed(1);
                return (
                  <div key={index} className="group">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-2xl">{entry.flag}</span>
                        <span className="text-sm text-ink-hi font-medium">{entry.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-ink-3">{percentage}%</span>
                        <span className="text-xs font-mono text-ink-3 bg-surface-2 px-2 py-1 rounded">
                          {entry.value}
                        </span>
                      </div>
                    </div>
                    <div className="h-2 bg-surface-3/50 rounded-full overflow-hidden">
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
        <div className="bg-surface-2/40 border border-line/50 rounded-2xl p-6 backdrop-blur-sm ring-1 ring-ink/5">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-green-500/20 rounded-lg text-green-400">
                <Router size={18} />
              </div>
              <h3 className="text-lg font-bold text-ink">节点协议分布</h3>
            </div>
          </div>

          <div className="space-y-3">
            {protocolData.length === 0 ? (
              <div className="text-center py-8 text-ink-3 text-sm">暂无节点协议数据</div>
            ) : (
              protocolData.map((entry, index) => {
                const totalNodes = protocolData.reduce((sum, p) => sum + p.value, 0);
                const percentage = totalNodes ? ((entry.value / totalNodes) * 100).toFixed(1) : 0;
                return (
                  <div key={index} className="group">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-sm text-ink-hi font-medium">{entry.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-ink-3">{percentage}%</span>
                        <span className="text-xs font-mono text-ink-3 bg-surface-2 px-2 py-1 rounded">
                          {entry.value}
                        </span>
                      </div>
                    </div>
                    <div className="h-2 bg-surface-3/50 rounded-full overflow-hidden">
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
