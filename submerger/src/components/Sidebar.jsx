import { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router';
import {
  LayoutDashboard,
  Plane,
  Server,
  Settings,
  Users,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
  Globe,
  FileCode,
  LogOut,
  Sun,
  Moon
} from 'lucide-react';
import { useTheme, toggleTheme } from '../utils/theme';

const menuItems = [
  {
    group: '概览',
    items: [
      { path: '/', icon: LayoutDashboard, label: '仪表盘' },
      { path: '/map', icon: Globe, label: '节点地图' },
    ]
  },
  {
    group: '订阅管理',
    items: [
      { path: '/subscriptions', icon: Plane, label: '机场管理' },
      { path: '/nodes', icon: Server, label: '节点管理' },
      { path: '/templates', icon: FileCode, label: '模板管理' },
    ]
  },
  {
    group: '系统',
    items: [
      { path: '/users', icon: Users, label: '用户管理' },
      { path: '/settings', icon: Settings, label: '系统设置' },
    ]
  }
];

export default function Sidebar({ collapsed, setCollapsed, onLogout }) {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [version, setVersion] = useState('...');
  const theme = useTheme();
  const isLight = theme === 'light';

  // Fetch version from API
  useEffect(() => {
    const controller = new AbortController();
    fetch('/health', { signal: controller.signal })
      .then(res => res.json())
      .then(data => {
        if (controller.signal.aborted) return;
        if (data.version) {
          setVersion(data.version);
        }
      })
      .catch((err) => {
        if (controller.signal.aborted || err.name === 'AbortError') return;
        setVersion('unknown');
      });
    return () => controller.abort();
  }, []);

  const NavItem = ({ item }) => {
    const isActive = location.pathname === item.path;
    const Icon = item.icon;

    return (
      <NavLink
        to={item.path}
        onClick={() => setMobileOpen(false)}
        className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group
          ${isActive
            ? 'bg-blue-500/10 text-blue-500'
            : 'text-ink-2 hover:bg-surface-2 hover:text-ink-hi'
          }`}
      >
        <Icon size={20} className={`flex-shrink-0 ${isActive ? 'text-blue-500' : 'text-ink-3 group-hover:text-ink-hi'}`} />
        {!collapsed && (
          <span className="text-sm font-medium truncate">{item.label}</span>
        )}
      </NavLink>
    );
  };

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center justify-between h-16 px-4 pr-14 lg:pr-4 border-b border-line-soft">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <Globe className="w-8 h-8 text-blue-500" />
            <span className="text-lg font-bold text-ink">SubMerger</span>
          </div>
        )}
        {collapsed && <Globe className="w-8 h-8 text-blue-500 mx-auto" />}

        <div className="flex items-center gap-1">
          {/* Theme toggle */}
          <button
            type="button"
            onClick={toggleTheme}
            className="flex items-center justify-center w-8 h-8 rounded-lg hover:bg-surface-2 text-ink-2 hover:text-ink transition-colors"
            title={isLight ? '切换到深色模式' : '切换到浅色模式'}
            aria-label={isLight ? '切换到深色模式' : '切换到浅色模式'}
          >
            {isLight ? <Moon size={18} /> : <Sun size={18} />}
          </button>

          {/* Desktop collapse button */}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden lg:flex items-center justify-center w-8 h-8 rounded-lg hover:bg-surface-2 text-ink-2 hover:text-ink transition-colors"
          >
            {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          </button>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3">
        {menuItems.map((group, idx) => (
          <div key={idx} className="mb-6">
            {!collapsed && (
              <h3 className="px-3 mb-2 text-xs font-semibold text-ink-3 uppercase tracking-wider">
                {group.group}
              </h3>
            )}
            <div className="space-y-1">
              {group.items.map((item) => (
                <NavItem key={item.path} item={item} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-line-soft">
        <button
          type="button"
          onClick={onLogout}
          className={`w-full flex items-center justify-center gap-2 px-3 py-2 mb-3 rounded-lg text-sm text-ink-2 hover:bg-red-500/10 hover:text-red-400 transition-colors ${collapsed ? 'px-2' : ''}`}
          title="退出登录"
        >
          <LogOut size={17} />
          {!collapsed && <span>退出登录</span>}
        </button>
        {!collapsed ? (
          <div className="text-xs text-ink-3 text-center">
            Clash Sub Merger v{version}
          </div>
        ) : (
          <div className="text-xs text-ink-3 text-center">v{version.split('.')[0]}</div>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setMobileOpen(true)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-surface-2 border border-line shadow-lg text-ink-2 hover:text-ink"
      >
        <Menu size={24} />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="lg:hidden fixed inset-0 z-40 bg-scrim/50"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar */}
      <aside
        className={`lg:hidden fixed inset-y-0 left-0 z-50 w-64 bg-surface transform transition-transform duration-300 ease-in-out
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <button
          onClick={() => setMobileOpen(false)}
          className="absolute top-4 right-4 p-2 rounded-lg text-ink-2 hover:text-ink hover:bg-surface-2"
        >
          <X size={20} />
        </button>
        <SidebarContent />
      </aside>

      {/* Desktop sidebar */}
      <aside
        className={`hidden lg:flex flex-col bg-surface border-r border-line-soft transition-all duration-300
          ${collapsed ? 'w-20' : 'w-64'}`}
      >
        <SidebarContent />
      </aside>
    </>
  );
}
