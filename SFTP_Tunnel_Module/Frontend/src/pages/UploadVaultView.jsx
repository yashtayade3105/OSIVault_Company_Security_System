import React from 'react';
import { FileText, Lock, Users, Calendar, ShieldCheck, CheckCircle2, ArrowRight, Sparkles } from 'lucide-react';

const UploadVaultView = ({ documents, onOpenUploadModal, onSelectDocument }) => {
  return (
    <div className="space-y-5">
      {/* Action Header */}
      <div className="saas-card border-l-4 border-l-rose-500 rounded-3xl p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="saas-badge-pink px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-rose-500 animate-spin" /> Processed Documents Vault
            </span>
          </div>
          <h3 className="font-black text-slate-800 text-xl mt-1.5">Processed EDI Documents</h3>
          <p className="text-xs text-slate-500">Showing parsed files and their server plaintext status inside <code className="text-rose-600 font-mono">D:\Transfers\Server_Directory</code></p>
        </div>
        <button
          onClick={onOpenUploadModal}
          className="saas-btn-primary px-5 py-3 font-black text-xs rounded-2xl transition-all flex items-center gap-2 cursor-pointer border border-rose-300 shrink-0"
        >
          <FileText className="w-4 h-4 text-white stroke-[2.5]" /> Upload & Parse File
        </button>
      </div>

      {/* Documents Table */}
      <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-700">
            <thead className="bg-rose-50/50 border-b border-rose-100 text-slate-600 font-extrabold uppercase tracking-wider">
              <tr>
                <th className="px-6 py-4">File Name & Type</th>
                <th className="px-6 py-4">Interchange Control #</th>
                <th className="px-6 py-4">Parsed Members</th>
                <th className="px-6 py-4">File Size</th>
                <th className="px-6 py-4">Disk Storage Format</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {documents.map((doc) => (
                <tr key={doc.id} className="hover:bg-rose-50/30 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-2xl bg-rose-50 border border-rose-100 text-rose-500 flex items-center justify-center font-black shrink-0">
                        <FileText className="w-5 h-5 stroke-[2.5]" />
                      </div>
                      <div>
                        <div className="font-extrabold text-slate-800 text-xs">{doc.file_name}</div>
                        <div className="text-[11px] font-mono text-rose-600 font-bold">{doc.file_type}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 font-mono text-slate-600 font-bold">
                    {doc.interchange_control_number || 'ISA_2985'}
                  </td>
                  <td className="px-6 py-4">
                    <span className="saas-badge-green px-3 py-1 font-black rounded-xl text-xs">
                      {doc.total_records_parsed} Records
                    </span>
                  </td>
                  <td className="px-6 py-4 font-mono text-slate-500 font-semibold">
                    {(doc.file_size / 1024).toFixed(1)} KB
                  </td>
                  <td className="px-6 py-4">
                    <span className="saas-badge-pink inline-flex items-center gap-1.5 text-xs font-black px-3 py-1 rounded-xl">
                      Plaintext EDI Data
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button 
                      onClick={() => onSelectDocument(doc)}
                      className="px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold text-xs transition-colors border border-slate-200 cursor-pointer"
                    >
                      Inspect Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UploadVaultView;
