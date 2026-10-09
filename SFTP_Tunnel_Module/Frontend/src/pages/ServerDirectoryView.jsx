import React from 'react';
import { Server, Lock, FileText, CheckCircle2, ShieldAlert, RefreshCw, HardDrive, Sparkles } from 'lucide-react';

const ServerDirectoryView = ({ directoryData, onRefresh }) => {
  const directory = directoryData?.directory || "D:\\Transfers\\Server_Directory";
  const files = directoryData?.results || [];

  return (
    <div className="space-y-5">
      {/* Target Directory Banner */}
      <div className="saas-card border-l-4 border-l-rose-500 rounded-3xl p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="saas-badge-pink px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-rose-500 animate-spin" /> Live Disk Storage Inspection
            </span>
            <span className="saas-badge-green px-2.5 py-1 rounded-lg text-xs font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Plaintext Prep Mode
            </span>
          </div>
          <h3 className="text-xl font-black text-slate-800 font-mono flex items-center gap-2 mt-2">
            <HardDrive className="w-6 h-6 text-rose-500 shrink-0" /> {directory}
          </h3>
          <p className="text-xs text-slate-600 max-w-2xl leading-relaxed">
            Files stored in this directory are written as raw plaintext EDI files. This allows us to verify and test OSIVault's encryption and superuser live decryption features on this target path.
          </p>
        </div>

        <button 
          onClick={onRefresh}
          className="saas-btn-primary px-5 py-3 rounded-2xl font-black text-xs flex items-center gap-2 border border-rose-300 transition-all shrink-0 cursor-pointer"
        >
          <RefreshCw className="w-4 h-4 stroke-[2.5]" /> Refresh Directory Files
        </button>
      </div>

      {/* Directory Files Table */}
      <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-700">
            <thead className="bg-rose-50/50 border-b border-rose-100 text-slate-600 font-extrabold uppercase tracking-wider">
              <tr>
                <th className="px-6 py-4">Filename</th>
                <th className="px-6 py-4">Full Disk Path</th>
                <th className="px-6 py-4">Size</th>
                <th className="px-6 py-4">Header Magic</th>
                <th className="px-6 py-4 text-right">Disk Format Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-xs">
              {files.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-slate-400 font-sans font-medium">
                    No files found in <code className="text-rose-600">{directory}</code> yet. Upload an EDI file to test!
                  </td>
                </tr>
              ) : (
                files.map((file, idx) => (
                  <tr key={idx} className="hover:bg-rose-50/30 transition-colors">
                    <td className="px-6 py-4 font-bold text-slate-800 flex items-center gap-3 font-sans text-xs">
                      <FileText className="w-4 h-4 text-rose-500 shrink-0" />
                      <span className="truncate max-w-xs">{file.filename}</span>
                    </td>
                    <td className="px-6 py-4 text-slate-500 truncate max-w-xs">
                      {file.full_path}
                    </td>
                    <td className="px-6 py-4 text-slate-800 font-bold">
                      {(file.size / 1024).toFixed(1)} KB
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-2.5 py-1 rounded-lg bg-slate-100 text-slate-700 font-bold border border-slate-200">
                        {file.header_magic || 'PLAINTEXT'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right font-sans">
                      <span className="saas-badge-pink inline-flex items-center gap-1.5 text-xs font-black px-3 py-1 rounded-xl">
                        Plaintext Data File
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ServerDirectoryView;
