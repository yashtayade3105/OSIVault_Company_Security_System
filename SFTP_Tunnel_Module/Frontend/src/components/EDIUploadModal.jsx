import React, { useState } from 'react';
import { X, FileUp, RefreshCw, CheckCircle2, AlertCircle, ShieldCheck, FolderLock, Sparkles } from 'lucide-react';
import { ediApi } from '../services/api';

export default function EDIUploadModal({ isOpen, onClose, onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [banner, setBanner] = useState(null);

  if (!isOpen) return null;

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setBanner(null);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setBanner({ type: 'error', message: 'Please select an EDI file from D:\\Transfers.' });
      return;
    }

    setLoading(true);
    setBanner({ type: 'info', message: `Uploading & Parsing '${file.name}' into Database & Server Vault (Plaintext)...` });

    try {
      const res = await ediApi.uploadFile(file);
      const data = res.data;

      if (data.status === 'success') {
        setBanner({ type: 'success', message: data.message });
        setTimeout(() => {
          if (onUploadSuccess) onUploadSuccess(data.document);
          onClose();
        }, 1500);
      } else {
        setBanner({ type: 'error', message: data.message || 'Failed to upload and parse EDI file.' });
      }
    } catch (err) {
      setBanner({ 
        type: 'error', 
        message: err.response?.data?.message || err.message || 'Error communicating with DRF backend API.' 
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-lg bg-white border border-rose-100 rounded-3xl shadow-2xl overflow-hidden p-6 sm:p-8 space-y-6 text-slate-800">
        
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-rose-100">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-rose-500 via-pink-400 to-emerald-400 flex items-center justify-center text-white shadow-md shrink-0">
              <FileUp className="w-6 h-6 stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center gap-1.5 text-xs text-rose-500 font-extrabold uppercase">
                <Sparkles className="w-3.5 h-3.5 animate-pulse" /> Light Pink & Mint Processor
              </div>
              <h3 className="text-xl font-black text-slate-800 tracking-tight">Upload EDI Document</h3>
            </div>
          </div>
          <button 
            onClick={onClose} 
            className="p-2 rounded-xl text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition-all cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Status Banner */}
        {banner && (
          <div className={`p-4 rounded-2xl text-xs sm:text-sm font-bold flex items-start gap-3 border shadow-xs transition-all ${
            banner.type === 'error' ? 'bg-rose-50 text-rose-700 border-rose-200' :
            banner.type === 'success' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' :
            'bg-pink-50 text-pink-800 border-pink-200'
          }`}>
            {banner.type === 'error' && <AlertCircle className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" />}
            {banner.type === 'success' && <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />}
            {banner.type === 'info' && <RefreshCw className="w-5 h-5 text-pink-500 shrink-0 mt-0.5 animate-spin" />}
            <span className="leading-relaxed">{banner.message}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleUploadSubmit} className="space-y-5">
          <div className="space-y-2">
            <label className="block text-xs font-black text-slate-600 uppercase tracking-wider">
              SELECT EDI TEXT FILE (FROM D:\Transfers)
            </label>
            <div className="border-2 border-dashed border-rose-200 hover:border-rose-400 rounded-2xl p-6 text-center bg-rose-50/30 transition-all cursor-pointer">
              <input
                type="file"
                accept=".txt,.edi,.dat,.txt*"
                onChange={handleFileChange}
                className="hidden"
                id="edi-file-input"
              />
              <label htmlFor="edi-file-input" className="cursor-pointer block space-y-2">
                <FolderLock className="w-10 h-10 text-rose-500 mx-auto stroke-[2]" />
                {file ? (
                  <div className="space-y-1">
                    <span className="text-sm font-black text-rose-600">{file.name}</span>
                    <p className="text-xs text-slate-500 font-mono">{(file.size / 1024).toFixed(1)} KB</p>
                  </div>
                ) : (
                  <div>
                    <span className="text-xs font-extrabold text-slate-700">Click to browse or drop EDI file here</span>
                    <p className="text-[11px] text-slate-400 mt-1">e.g. D:\Transfers\AHH_AMO\backups\AHH_ABC_Elig_Full_251231103923.TXT</p>
                  </div>
                )}
              </label>
            </div>
          </div>

          {/* Action Button */}
          <button
            type="submit"
            disabled={loading || !file}
            className="saas-btn-primary w-full py-4 rounded-2xl font-black text-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 border border-rose-300"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-white" />
                <span>Parsing Segments & Writing to Server Directory...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4 text-white stroke-[2.5]" />
                <span>Parse to Database & Save to Directory</span>
              </>
            )}
          </button>
        </form>

      </div>
    </div>
  );
}
