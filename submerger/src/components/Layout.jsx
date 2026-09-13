import { useState } from 'react';
import Sidebar from './Sidebar';

export default function Layout({ children, onLogout }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-base">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} onLogout={onLogout} />
      <main className="flex-1 min-w-0 overflow-auto">
        <div className="p-4 sm:p-6 lg:p-8 pt-16 lg:pt-8">
          {children}
        </div>
      </main>
    </div>
  );
}
