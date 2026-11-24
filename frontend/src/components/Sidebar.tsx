import React from 'react';
import { Shield, Activity, Bell, FileText } from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, setCurrentTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'scans', label: 'Email Scans', icon: Shield },
    { id: 'alerts', label: 'Security Alerts', icon: Bell },
    { id: 'audit', label: 'Audit Trail', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col justify-between p-4">
      <div>
        <div className="flex items-center space-x-3 px-2 py-4 mb-6 border-b border-gray-800">
          <div className="p-2 bg-blue-600/20 text-blue-500 rounded-lg">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-bold text-lg text-white tracking-wide">MailSentra</h1>
            <p className="text-xs text-gray-500 font-mono">v1.0.0-phase1</p>
          </div>
        </div>

        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentTab(item.id)}
                className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="pt-4 border-t border-gray-800">
        <div className="px-3 py-2 bg-gray-950/60 rounded-lg border border-gray-800/80">
          <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
            <span className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>Engine Status</span>
            </span>
            <span className="text-emerald-400 font-mono font-medium">READY</span>
          </div>
          <p className="text-[11px] text-gray-500 truncate">FastAPI ASGI Core</p>
        </div>
      </div>
    </aside>
  );
};
