import React, { useState } from 'react';
import Sidebar from './Sidebar';

export default function Layout({ children, onLogout }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-gray-950">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} onLogout={onLogout} />
      <main className="flex-1 overflow-auto">
        <div className="p-6 lg:p-8 pt-16 lg:pt-8">
          {children}
        </div>
      </main>
    </div>
  );
}
