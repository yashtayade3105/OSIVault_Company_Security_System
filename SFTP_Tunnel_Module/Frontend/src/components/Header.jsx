import React from 'react';
import { ShieldCheck, FileUp, Bell, Server, Sparkles, FolderLock, Key } from 'lucide-react';

const Header = ({ activeTab, onOpenUploadModal, onOpenAuthModal }) => {
  const getTabTitle = (tab) => {
    switch (tab) {
      case 'dashboard': return 'EDI Vault Operations Command Center';
      case 'osivault': return 'OSIVault Security Core (auth, sftp, fields, audit)';
      case 'upload': return 'EDI File Processing & Storage Vault';
      case 'members': return 'Parsed Member Records & Eligibility';
      case 'directory': return 'Disk Storage Vault (D:\\Transfers\\Server_Directory)';
      case 'audit': return 'Audit Trail & Integrity Log';
      default: return 'SFTP Tunnel Module Operations';
    }
  };

  return (
    <header className="bg-white/90 backdrop-blur border-b border-rose-100 px-6 py-4 flex items-center justify-between sticky top-0 z-30 shadow-xs">
      <div>
        <div className="flex items-center gap-2">
          <span className="saas-badge-pink px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-rose-500 animate-pulse" /> Full OSIVault Integration Active
          </span>
          <span className="text-xs text-emerald-700 font-mono font-bold">4-Module Security Suite</span>
        </div>
        <h2 className="text-xl font-black text-slate-800 tracking-tight mt-0.5">{getTabTitle(activeTab)}</h2>
      </div>

      <div className="flex items-center gap-3">
        {/* osivault.auth Pop-up Portal Button */}
        <button
          onClick={onOpenAuthModal}
          className="saas-badge-pink px-3.5 py-2 font-extrabold text-xs rounded-xl transition-all flex items-center gap-2 cursor-pointer border border-pink-300 shadow-xs hover:bg-pink-100"
        >
          <Key className="w-4 h-4 text-pink-600 stroke-[2.5]" />
          <span>osivault.auth Portal</span>
        </button>

        {/* Directory Path Badge */}
        <div className="hidden lg:flex items-center gap-2 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs px-3.5 py-2 rounded-xl font-mono shadow-xs">
          <FolderLock className="w-4 h-4 text-emerald-600" />
          <span className="font-bold text-emerald-900">D:\Transfers\Server_Directory</span>
        </div>

        {/* Upload Button */}
        <button
          onClick={onOpenUploadModal}
          className="saas-btn-primary px-4 py-2.5 font-extrabold text-xs rounded-xl transition-all flex items-center gap-2 cursor-pointer border border-rose-300"
        >
          <FileUp className="w-4 h-4 text-white stroke-[2.5]" />
          <span>Upload EDI File</span>
        </button>
      </div>
    </header>
  );
};

export default Header;
