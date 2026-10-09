import React from 'react';
import { 
  LayoutDashboard, 
  FileUp, 
  Users, 
  FolderLock, 
  History, 
  ShieldCheck,
  Server,
  Sparkles,
  Lock
} from 'lucide-react';

const Sidebar = ({ activeTab, setActiveTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'SaaS Command Center', icon: LayoutDashboard },
    { id: 'osivault', label: 'OSIVault Security Suite', icon: ShieldCheck, highlight: true, badge: 'CORE' },
    { id: 'upload', label: 'EDI Upload & Vault', icon: FileUp },
    { id: 'members', label: 'Parsed Member DB', icon: Users },
    { id: 'directory', label: 'Server Vault Storage', icon: Server },
    { id: 'audit', label: 'EDI Transfer Audit Log', icon: History },
  ];

  return (
    <aside className="w-64 bg-white border-r border-rose-100 min-h-screen flex flex-col justify-between p-4 sticky top-0 h-screen overflow-y-auto shadow-sm">
      <div>
        {/* Brand Logo */}
        <div className="flex items-center gap-3 px-3 py-4 mb-6 border-b border-rose-100">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-rose-500 via-pink-400 to-emerald-400 flex items-center justify-center text-white shadow-md border border-rose-200">
            <FolderLock className="w-6 h-6 stroke-[2.5]" />
          </div>
          <div>
            <h1 className="font-black text-slate-800 tracking-tight text-lg leading-none">SFTP Vault</h1>
            <p className="text-[11px] text-rose-500 font-extrabold tracking-wide mt-1 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-emerald-500 animate-pulse" /> OSIVault Integrated
            </p>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-3 rounded-xl text-xs font-extrabold transition-all duration-200 cursor-pointer ${
                  isActive
                    ? 'bg-gradient-to-r from-rose-50 to-pink-50 text-rose-600 border-l-4 border-l-rose-500 border border-rose-200 shadow-xs'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-emerald-50/60 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-rose-500 stroke-[2.5]' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="saas-badge-pink text-[9px] uppercase font-black px-2 py-0.5 rounded-full">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Vault Security Footer */}
      <div className="bg-gradient-to-br from-emerald-50 to-rose-50 border border-emerald-200 rounded-2xl p-4 text-xs space-y-2.5 shadow-xs">
        <div className="flex items-center justify-between">
          <span className="font-extrabold text-emerald-900 flex items-center gap-1.5 text-xs">
            <ShieldCheck className="w-4 h-4 text-emerald-600" /> OSIVault 4-Module Core
          </span>
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span>
        </div>
        <p className="text-[11px] text-slate-600 leading-relaxed font-mono">
          Target directory: <strong className="text-slate-900 font-bold block mt-0.5">D:\Transfers\Server_Directory</strong>
        </p>
      </div>
    </aside>
  );
};

export default Sidebar;
