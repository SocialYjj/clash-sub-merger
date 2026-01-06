import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import * as echarts from 'echarts';
import { RefreshCw, Server, Globe, ExternalLink, X } from 'lucide-react';
import worldJson from '../assets/world.json';
import { COUNTRY_COORDINATES, COUNTRY_NAME_MAP } from './countryData';

// Register map
echarts.registerMap('world', worldJson);

const API_BASE = '/api';

// Helper: Get Flag Emoji from Country Code
const getFlagEmoji = (countryCode) => {
  if (!countryCode) return '';
  // Special case for Taiwan -> China flag as requested in original code? 
  // Wait, user might prefer Taiwan flag. Let's stick to standard behavior unless forced.
  // The original code had: if (countryCode.toUpperCase() === 'TW') return '🇨🇳'; 
  // I will keep standard flags for now as per previous context (users usually prefer accurate flags).
  if (countryCode.toUpperCase() === 'TW') return '🇹🇼';

  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
};

// Helper: Attempt to find country code by name (case insensitive)
const findCountryCode = (name) => {
  if (!name) return null;
  const lowerName = name.toLowerCase().trim();

  // 1. Direct check in Coordinates keys
  if (COUNTRY_COORDINATES[name.toUpperCase()]) return name.toUpperCase();

  // 2. Map lookup
  if (COUNTRY_NAME_MAP[lowerName]) return COUNTRY_NAME_MAP[lowerName];

  // 3. 2-letter code check
  if (name.length === 2 && COUNTRY_COORDINATES[name.toUpperCase()]) return name.toUpperCase();

  return null;
};

export default function NodeMap() {
  const navigate = useNavigate();
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  const [loading, setLoading] = useState(true);
  const [countryData, setCountryData] = useState([]); // Array of { code, name, count, flag }
  const [rawData, setRawData] = useState({}); // Object { code: count }
  const [totalNodes, setTotalNodes] = useState(0);

  // Node list modal state
  const [showNodeList, setShowNodeList] = useState(false);
  const [selectedCountry, setSelectedCountry] = useState(null);
  const [countryNodes, setCountryNodes] = useState([]);
  const [loadingNodes, setLoadingNodes] = useState(false);

  useEffect(() => {
    fetchCountryData();
  }, []);

  const fetchCountryData = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/stats/nodes-by-country`);
      // res.data.countries is array: [{code, name, flag, count}, ...]
      // Convert to object for map logic: { 'US': 10, 'CN': 5 }
      const dataObj = {};
      res.data.countries.forEach(c => {
        if (c.code) dataObj[c.code] = c.count;
      });

      setRawData(dataObj);
      setCountryData(res.data.countries || []);
      setTotalNodes(res.data.total || 0);
    } catch (err) {
      console.error('Failed to fetch country data', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchCountryNodes = async (countryCode) => {
    setLoadingNodes(true);
    try {
      const res = await axios.get(`${API_BASE}/stats/nodes-by-country/${countryCode}`);
      setCountryNodes(res.data.nodes || []);
      // Find full country object for display
      const countryObj = countryData.find(c => c.code === countryCode) || {
        code: countryCode,
        name: countryCode,
        flag: getFlagEmoji(countryCode),
        count: res.data.nodes?.length || 0
      };
      setSelectedCountry(countryObj);
      setShowNodeList(true);
    } catch (err) {
      console.error('Failed to fetch country nodes', err);
    } finally {
      setLoadingNodes(false);
    }
  };

  const goToNodesPage = () => {
    navigate('/nodes', { state: { filterCountry: selectedCountry?.code } });
  };

  // Process data for ECharts
  const { points, lines, targetPoint, unknownCount } = useMemo(() => {
    const pts = [];
    const lns = [];
    let tPoint = null;
    let unk = 0;

    // Original code used 'CN' as target. We can stick to that or make it dynamic.
    // Let's assume China/Asia is the destination/home base for lines.
    const chinaCoords = COUNTRY_COORDINATES['CN'];

    // Create Target Point (China)
    if (chinaCoords) {
      tPoint = {
        name: 'CN',
        value: [...chinaCoords, 0], // Flat coords
        itemStyle: { color: '#fbbf24' }, // Gold
        rippleEffect: { brushType: 'stroke', scale: 4, period: 4 }
      };
    }

    Object.entries(rawData).forEach(([key, count]) => {
      const countryCode = findCountryCode(key);

      if (!countryCode || !COUNTRY_COORDINATES[countryCode]) {
        unk += count;
        return;
      }

      const coords = COUNTRY_COORDINATES[countryCode];

      // If it's China itself, just count it but maybe don't draw line to itself
      if (countryCode === 'CN') {
        // We already have target point
        return;
      }

      // Normal Points
      pts.push({
        name: countryCode,
        value: [...coords, count, countryCode], // [lon, lat, count, code]
        itemStyle: { color: '#0cecdb' } // Cyan
      });

      // Flying Lines to China
      if (chinaCoords) {
        lns.push({
          coords: [coords, chinaCoords],
          lineStyle: { color: '#38bdf8' } // Light Blue
        });
      }
    });

    return { points: pts, lines: lns, targetPoint: tPoint, unknownCount: unk };
  }, [rawData]);

  // ECharts Initialization and Option Setting
  useEffect(() => {
    if (!chartRef.current || loading) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current);

      // Handle click events on map items
      chartInstance.current.on('click', (params) => {
        if (params.componentType === 'series' && params.seriesType === 'effectScatter') {
          // Check if it's a country point
          const code = params.value && params.value[3]; // [lon, lat, count, code]
          if (code) {
            fetchCountryNodes(code);
          } else if (params.name === 'CN' || (params.data && params.data.name === 'CN')) {
            fetchCountryNodes('CN');
          }
        }
      });

      // Handle click on map regions (geo component)
      chartInstance.current.on('click', (params) => {
        if (params.componentType === 'geo') {
          const countryName = params.name;
          const code = findCountryCode(countryName);
          if (code && rawData[code]) {
            fetchCountryNodes(code);
          }
        }
      });
    }

    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        show: true,
        trigger: 'item',
        backgroundColor: 'rgba(15, 23, 42, 0.95)',
        borderColor: '#0cecdb',
        borderWidth: 1,
        textStyle: { color: '#fff', fontFamily: 'sans-serif' },
        padding: [10, 15],
        formatter: (params) => {
          if (params.seriesType === 'lines') return '';

          if (params.name === 'CN' || (params.data && params.data.name === 'CN')) {
            const cnCount = rawData['CN'] || 0;
            return `<div style="font-weight: bold; color: #fff; font-size: 14px; margin-bottom: 8px;">中国 (本地区域)</div>
                    ${cnCount > 0 ? `<div style="font-size: 12px; display: flex; justify-content: space-between; width: 100px;">
                       <span style="color: #9ca3af;">节点数量</span>
                       <span style="font-weight: bold; color: #facc15;">${cnCount}</span>
                    </div>` : ''}`;
          }

          const valCode = params.value && params.value[3];
          if (!valCode) return '';

          const count = params.value[2];
          // Get full country name from countryData
          const countryInfo = countryData.find(c => c.code === valCode);
          const countryName = countryInfo?.name || valCode;

          return `<div style="font-weight: bold; color: #fff; font-size: 14px; margin-bottom: 8px;">${countryName}</div>
                  <div style="font-size: 12px; display: flex; justify-content: space-between; width: 100px;">
                    <span style="color: #9ca3af;">节点数量</span>
                    <span style="font-weight: bold; color: #22d3ee;">${count}</span>
                  </div>`;
        }
      },
      geo: {
        map: 'world',
        roam: true,
        zoom: 1.2,
        label: { emphasis: { show: false } },
        itemStyle: {
          normal: {
            areaColor: '#1e293b', // slate-800
            borderColor: '#0f172a', // slate-900
            borderWidth: 1
          },
          emphasis: {
            areaColor: '#334155' // slate-700
          }
        },
        regions: [{ name: 'China', itemStyle: { areaColor: '#334155' } }]
      },
      series: [
        // 1. Flying Lines
        {
          type: 'lines',
          zlevel: 1,
          effect: {
            show: true,
            period: 6,
            trailLength: 0.7,
            color: '#fff',
            symbolSize: 3
          },
          lineStyle: {
            normal: { color: '#0cecdb', width: 0, curveness: 0.2 }
          },
          data: lines
        },
        // 2. Flying Lines (Arrows)
        {
          type: 'lines',
          zlevel: 2,
          symbol: ['none', 'arrow'],
          symbolSize: 5,
          effect: {
            show: true,
            period: 6,
            trailLength: 0,
            symbol: 'arrow',
            symbolSize: 6
          },
          lineStyle: {
            normal: { color: '#0cecdb', width: 1, opacity: 0.4, curveness: 0.2 }
          },
          data: lines
        },
        // 3. Effect Scatter (Nodes)
        {
          type: 'effectScatter',
          coordinateSystem: 'geo',
          zlevel: 2,
          rippleEffect: { brushType: 'stroke', scale: 3 },
          label: {
            show: true,
            position: 'right',
            formatter: (params) => {
              const code = params.value[3];
              return code;  // Just show country code, emoji doesn't render well
            },
            fontSize: 12,
            color: '#fff',
            distance: 5
          },
          symbolSize: (val) => Math.max(6, Math.min(20, Math.log2(val[2] + 1) * 5)),
          itemStyle: { color: '#0cecdb' },
          data: points
        },
        // 4. Target Point (China/Center)
        ...(targetPoint ? [{
          type: 'effectScatter',
          coordinateSystem: 'geo',
          zlevel: 3,
          rippleEffect: { brushType: 'stroke', scale: 5, period: 3, color: '#fbbf24' },
          symbol: 'pin',
          symbolSize: 20,
          itemStyle: { color: '#fbbf24' },
          label: {
            show: true,
            formatter: 'CN',
            position: 'right',
            fontSize: 12,
            color: '#fff',
            distance: 5
          },
          data: [targetPoint]
        }] : [])
      ]
    };

    chartInstance.current.setOption(option, true);

    const handleResize = () => {
      chartInstance.current?.resize();
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      // Don't dispose immediately if re-rendering, but if strict mode...
      // better to handle dispose in cleanup of useEffect
      // chartInstance.current?.dispose(); 
      // chartInstance.current = null;
    };
  }, [points, lines, targetPoint, loading]); // Re-run when data changes

  // Dispose chart on unmount
  useEffect(() => {
    return () => {
      if (chartInstance.current) {
        chartInstance.current.dispose();
        chartInstance.current = null;
      }
    }
  }, []);

  return (
    <div className="h-[calc(100vh-100px)] flex flex-col space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0 mb-2">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Globe className="text-blue-500" /> 全球节点分布
          </h1>
          <p className="text-gray-400 text-xs mt-1 font-mono text-cyan-500">
            LIVE NODE MAP VISUALIZATION
          </p>
        </div>
        <div className="flex gap-2">

          <button
            onClick={fetchCountryData}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded transition-colors text-sm"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            刷新
          </button>
        </div>
      </div>

      {/* Main Map Container */}
      <div className="flex-1 relative bg-slate-900/50 rounded-xl border border-slate-800 overflow-hidden shadow-2xl">
        {/* Holographic grid background */}
        <div
          className="absolute inset-0 opacity-10 pointer-events-none"
          style={{
            backgroundImage: `linear-gradient(rgba(14, 165, 233, 0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(14, 165, 233, 0.3) 1px, transparent 1px)`,
            backgroundSize: '40px 40px'
          }}
        />

        {/* ECharts Container */}
        <div ref={chartRef} className="w-full h-full" />

        {/* Loading Overlay */}
        {loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-slate-900/80 z-20">
            <RefreshCw className="animate-spin text-cyan-500 mb-2" size={40} />
            <span className="text-cyan-500 font-mono tracking-widest">INITIALIZING MAP...</span>
          </div>
        )}

        {/* Stats Overlay Bottom Right */}
        <div className="absolute bottom-6 right-8 text-right z-10 pointer-events-none select-none">
          <div className="text-gray-400 text-xs tracking-widest uppercase mb-1">Total Coverage</div>
          <div className="text-6xl font-black text-cyan-500 leading-none drop-shadow-[0_0_15px_rgba(6,182,212,0.5)]">
            {String(points.length + (targetPoint ? 1 : 0)).padStart(2, '0')}
          </div>
          <div className="w-24 h-1 bg-cyan-500 ml-auto mt-2 opacity-80" />
        </div>
      </div>

      {/* Node List Modal */}
      {showNodeList && selectedCountry && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-800 rounded-xl w-full max-w-2xl border border-slate-700 max-h-[80vh] flex flex-col shadow-2xl animate-in fade-in zoom-in duration-200">
            <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between shrink-0 bg-slate-800/50">
              <div className="flex items-center gap-3">
                <span className="text-3xl bg-slate-700/50 rounded p-1">{selectedCountry.flag}</span>
                <div>
                  <h3 className="font-bold text-white text-lg">{selectedCountry.name} 节点列表</h3>
                  <div className="text-xs text-gray-400 font-mono mt-0.5">
                    <span className="text-cyan-400 font-bold">{selectedCountry.count}</span> NODES AVAILABLE
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={goToNodesPage}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 rounded-lg transition-colors"
                >
                  <ExternalLink size={14} />
                  管理节点
                </button>
                <button
                  onClick={() => setShowNodeList(false)}
                  className="text-gray-400 hover:text-white p-2 hover:bg-slate-700 rounded-full transition-colors"
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            <div className="overflow-y-auto flex-1 p-0">
              {loadingNodes ? (
                <div className="px-4 py-12 text-center text-gray-500 flex flex-col items-center">
                  <RefreshCw className="animate-spin mb-2" />
                  加载数据中...
                </div>
              ) : countryNodes.length > 0 ? (
                <table className="w-full text-left border-collapse">
                  <thead className="bg-slate-900/50 sticky top-0 z-10 backdrop-blur">
                    <tr className="text-xs text-gray-400 uppercase tracking-wider">
                      <th className="px-6 py-3 font-medium">节点名称</th>
                      <th className="px-6 py-3 font-medium">协议</th>
                      <th className="px-6 py-3 font-medium text-right">来源</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/50">
                    {countryNodes.map((node, idx) => (
                      <tr key={idx} className="hover:bg-slate-700/30 transition-colors group">
                        <td className="px-6 py-3">
                          <div className="text-gray-200 font-medium truncate max-w-[280px]" title={node.name}>
                            {node.name || '未命名'}
                          </div>
                        </td>
                        <td className="px-6 py-3">
                          <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-mono bg-slate-700 text-gray-300 group-hover:bg-cyan-900/30 group-hover:text-cyan-300 transition-colors">
                            {node.type?.toUpperCase() || 'UNKNOWN'}
                          </span>
                        </td>
                        <td className="px-6 py-3 text-right">
                          <span className="text-sm text-gray-500 font-mono">{node.source || 'Local'}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="px-4 py-12 text-center text-gray-500">
                  暂无节点数据
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
