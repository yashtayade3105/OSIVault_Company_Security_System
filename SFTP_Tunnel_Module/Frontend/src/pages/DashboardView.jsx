import React from 'react';
import { 
  FileText, 
  Users, 
  Lock, 
  History, 
  Building2, 
  ShieldCheck, 
  ArrowRight,
  Server,
  CheckCircle2,
  Sparkles,
  Zap,
  FolderLock
} from 'lucide-react';

const DashboardView = ({ stats, onNavigate }) => {
  const activeStats = stats || {
    total_documents: 18,
    total_members_parsed: 75240,
    encrypted_vault_files: 0,
    total_audit_events: 36,
    server_storage_directory: "D:\\Transfers\\Server_Directory",
    file_type_distribution: [
      { type: "834 Benefit Enrollment", count: 14 },
      { type: "835 Payment Remittance", count: 4 },
      { type: "270 Eligibility Request", count: 2 },
    ]
  };

  return (
    <div className="space-y-6">
      {/* Vibrant Light Hero Banner */}
      <div className="bg-gradient-to-r from-rose-500 via-pink-500 to-emerald-500 rounded-3xl p-6 shadow-xl relative overflow-hidden text-white border border-rose-200">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 rounded-full bg-white/20 text-white text-xs font-black uppercase tracking-wider border border-white/30 flex items-center gap-1.5 shadow-xs">
                <Sparkles className="w-3.5 h-3.5 text-white animate-spin" /> SaaS Light Pink & Mint Edition
              </span>
              <span className="text-xs text-rose-100 font-mono font-medium">Plaintext Server Prep Active</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-black tracking-tight">
              HIPAA EDI Processing & Server Storage Platform
            </h1>
            <p className="text-xs md:text-sm text-rose-50 max-w-2xl leading-relaxed">
              Files uploaded to the platform are automatically parsed into relational database records and saved as plain text files in <code className="bg-white/20 px-2 py-0.5 rounded text-white font-mono font-bold">D:\Transfers\Server_Directory</code> (ready for OSIVault security testing).
            </p>
          </div>
          <button
            onClick={() => onNavigate('upload')}
            className="px-5 py-3 rounded-2xl bg-white hover:bg-rose-50 text-rose-600 font-black text-xs shadow-lg flex items-center gap-2 transition-all cursor-pointer border border-white shrink-0"
          >
            <Zap className="w-4 h-4 fill-rose-600 stroke-none" />
            <span>Upload EDI File Now</span>
            <ArrowRight className="w-4 h-4 stroke-[3]" />
          </button>
        </div>
      </div>

      {/* Bright Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="saas-card rounded-2xl p-5 shadow-sm space-y-2 transition-all">
          <div className="flex items-center justify-between text-slate-500 text-xs font-bold uppercase tracking-wider">
            <span>EDI Documents</span>
            <div className="p-2.5 rounded-2xl bg-rose-50 text-rose-500 border border-rose-100">
              <FileText className="w-5 h-5 stroke-[2.5]" />
            </div>
          </div>
          <div className="text-3xl font-black text-slate-800">{activeStats.total_documents}</div>
          <p className="text-xs text-rose-600 font-extrabold">Processed ANSI X12 Files</p>
        </div>

        <div className="saas-card rounded-2xl p-5 shadow-sm space-y-2 transition-all">
          <div className="flex items-center justify-between text-slate-500 text-xs font-bold uppercase tracking-wider">
            <span>Parsed Members</span>
            <div className="p-2.5 rounded-2xl bg-emerald-50 text-emerald-600 border border-emerald-100">
              <Users className="w-5 h-5 stroke-[2.5]" />
            </div>
          </div>
          <div className="text-3xl font-black text-slate-800">{activeStats.total_members_parsed.toLocaleString()}</div>
          <p className="text-xs text-emerald-600 font-extrabold">Relational Database Records</p>
        </div>

        <div className="saas-card rounded-2xl p-5 shadow-sm space-y-2 transition-all">
          <div className="flex items-center justify-between text-slate-500 text-xs font-bold uppercase tracking-wider">
            <span>Plaintext Server Files</span>
            <div className="p-2.5 rounded-2xl bg-pink-50 text-pink-500 border border-pink-100">
              <FolderLock className="w-5 h-5 stroke-[2.5]" />
            </div>
          </div>
          <div className="text-3xl font-black text-slate-800">{activeStats.total_documents}</div>
          <p className="text-xs text-pink-600 font-extrabold">Ready for OSIVault Testing</p>
        </div>

        <div className="saas-card rounded-2xl p-5 shadow-sm space-y-2 transition-all">
          <div className="flex items-center justify-between text-slate-500 text-xs font-bold uppercase tracking-wider">
            <span>Audit Events Logged</span>
            <div className="p-2.5 rounded-2xl bg-teal-50 text-teal-600 border border-teal-100">
              <History className="w-5 h-5 stroke-[2.5]" />
            </div>
          </div>
          <div className="text-3xl font-black text-slate-800">{activeStats.total_audit_events}</div>
          <p className="text-xs text-teal-600 font-extrabold">SHA-256 Verified Logs</p>
        </div>
      </div>

      {/* Target Directory Banner */}
      <div className="saas-card rounded-2xl p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-l-4 border-l-emerald-500">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-emerald-500 to-teal-400 flex items-center justify-center text-white font-black shadow-md shrink-0">
            <Server className="w-6 h-6 stroke-[2.5]" />
          </div>
          <div>
            <h4 className="text-base font-extrabold text-slate-800 flex items-center gap-2">
              Target Vault Directory:
              <span className="font-mono text-emerald-800 bg-emerald-50 px-3 py-1 rounded-xl border border-emerald-200 text-sm font-bold">
                {activeStats.server_storage_directory}
              </span>
            </h4>
            <p className="text-xs text-slate-500 mt-1">
              Parsed EDI files are saved as plain text files in this folder so we can test OSIVault's encryption and superuser decryption.
            </p>
          </div>
        </div>

        <button
          onClick={() => onNavigate('directory')}
          className="px-4 py-2.5 rounded-xl bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shrink-0"
        >
          <span>Inspect Server Files</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Classification Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Document Breakdown */}
        <div className="saas-card rounded-2xl p-6 shadow-sm space-y-4 col-span-2">
          <h3 className="font-extrabold text-slate-800 text-base flex items-center gap-2">
            <Building2 className="w-5 h-5 text-rose-500" /> Processed EDI File Classification
          </h3>
          <div className="space-y-3">
            {activeStats.file_type_distribution.map((item, idx) => (
              <div key={idx} className="bg-slate-50 border border-slate-100 rounded-xl p-3.5 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 rounded-full bg-rose-500 shadow-xs"></div>
                  <span className="text-xs font-extrabold text-slate-700">{item.type}</span>
                </div>
                <span className="saas-badge-pink px-3 py-1 text-xs font-black rounded-lg">
                  {item.count} Documents
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* System Health */}
        <div className="saas-card rounded-2xl p-6 shadow-sm space-y-4">
          <h3 className="font-extrabold text-slate-800 text-base flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-600" /> System Integration Status
          </h3>
          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between p-3 rounded-xl bg-emerald-50 border border-emerald-100 text-emerald-900 font-bold">
              <span>SaaS EDI Processor</span>
              <span className="text-emerald-700 flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4" /> Ready
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-rose-50 border border-rose-100 text-rose-900 font-bold">
              <span>OSIVault Integration</span>
              <span className="text-rose-600 font-bold">Pending Approval</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-700 font-bold">
              <span>Target Directory</span>
              <span className="text-slate-900 font-mono font-bold">Verified</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardView;
