import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Plane,
  Server,
  Map,
  Settings,
  Users,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
  Globe,
  Clock,
  Database,
  FileCode
} from 'lucide-react';

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

export default function Sidebar({ collapsed, setCollapsed }) {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

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
            : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
          }`}
      >
        <Icon size={20} className={`flex-shrink-0 ${isActive ? 'text-blue-500' : 'text-gray-500 group-hover:text-gray-300'}`} />
        {!collapsed && (
          <span className="text-sm font-medium truncate">{item.label}</span>
        )}
      </NavLink>
    );
  };

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center justify-between h-16 px-4 border-b border-gray-800">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <Globe className="w-8 h-8 text-blue-500" />
            <span className="text-lg font-bold text-white">SubMerger</span>
          </div>
        )}
        {collapsed && <Globe className="w-8 h-8 text-blue-500 mx-auto" />}

        {/* Desktop collapse button */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="hidden lg:flex items-center justify-center w-8 h-8 rounded-lg hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
        >
          {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3">
        {menuItems.map((group, idx) => (
          <div key={idx} className="mb-6">
            {!collapsed && (
              <h3 className="px-3 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
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
      <div className="p-4 border-t border-gray-800">
        {!collapsed ? (
          <div className="text-xs text-gray-500 text-center">
            Clash Sub Merger v2.2.1
          </div>
        ) : (
          <div className="text-xs text-gray-500 text-center">v2</div>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setMobileOpen(true)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-gray-800 text-gray-400 hover:text-white"
      >
        <Menu size={24} />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="lg:hidden fixed inset-0 z-40 bg-black/50"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar */}
      <aside
        className={`lg:hidden fixed inset-y-0 left-0 z-50 w-64 bg-gray-900 transform transition-transform duration-300 ease-in-out
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <button
          onClick={() => setMobileOpen(false)}
          className="absolute top-4 right-4 p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800"
        >
          <X size={20} />
        </button>
        <SidebarContent />
      </aside>

      {/* Desktop sidebar */}
      <aside
        className={`hidden lg:flex flex-col bg-gray-900 border-r border-gray-800 transition-all duration-300
          ${collapsed ? 'w-20' : 'w-64'}`}
      >
        <SidebarContent />
      </aside>
    </>
  );
}
