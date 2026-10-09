import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Key, 
  Lock, 
  Terminal, 
  FileText, 
  CheckCircle2, 
  RefreshCw, 
  Cpu, 
  Database, 
  Eye, 
  Sparkles,
  AlertTriangle,
  FolderLock,
  GitCommit,
  Search,
  RotateCw
} from 'lucide-react';
import { ediApi } from '../services/api';

const OSIVaultSecurityView = ({ onOpenAuthModal }) => {
  const [activeSubTab, setActiveSubTab] = useState('fields');
  const [superusers, setSuperusers] = useState([]);
  const [sftpLogs, setSftpLogs] = useState([]);
  const [fieldsData, setFieldsData] = useState([]);
  const [directoryFiles, setDirectoryFiles] = useState([]);

  // osivault.audit state
  const [auditTargetTable, setAuditTargetTable] = useState('document');
  const [auditLogs, setAuditLogs] = useState([]);
  const [chainReport, setChainReport] = useState(null);
  const [checkpointReport, setCheckpointReport] = useState(null);

  // osivault.fields search state
  const [searchQuery, setSearchQuery] = useState('Z30366883');
  const [searchResults, setSearchResults] = useState(null);

  const [loading, setLoading] = useState(false);
  const [actionBanner, setActionBanner] = useState(null);

  // osivault.sftp decrypt state
  const [decryptFilename, setDecryptFilename] = useState('');
  const [decryptUser, setDecryptUser] = useState('sftp_admin');
  const [decryptPass, setDecryptPass] = useState('SecureOSIVault2026!');
  const [decryptResult, setDecryptResult] = useState(null);

  // osivault.auth state
  const [authData, setAuthData] = useState(null);
  const [otpEmail, setOtpEmail] = useState('developer@onesmarter.com');
  const [otpCode, setOtpCode] = useState('');
  const [regUsername, setRegUsername] = useState('osivault_developer');
  const [regPassword, setRegPassword] = useState('SecureOSIVault2026!');

  const fetchOSIVaultData = async () => {
    setLoading(true);
    try {
      const [usersRes, logsRes, fieldsRes, dirRes, auditRes, authRes] = await Promise.all([
        ediApi.getOSIVaultSuperusers().catch(() => ({ data: { results: [] } })),
        ediApi.getOSIVaultSFTPLogs().catch(() => ({ data: { results: [] } })),
        ediApi.getOSIVaultFieldsInspect().catch(() => ({ data: { results: [] } })),
        ediApi.getServerDirectoryFiles().catch(() => ({ data: { results: [] } })),
        ediApi.getOSIVaultAuditLogs(auditTargetTable).catch(() => ({ data: { results: [] } })),
        ediApi.getOSIVaultAuthInspect().catch(() => ({ data: null })),
      ]);

      if (usersRes.data?.results) setSuperusers(usersRes.data.results);
      if (logsRes.data?.results) setSftpLogs(logsRes.data.results);
      if (fieldsRes.data?.results) setFieldsData(fieldsRes.data.results);
      if (dirRes.data?.results) setDirectoryFiles(dirRes.data.results);
      if (auditRes.data?.results) setAuditLogs(auditRes.data.results);
      if (authRes.data) setAuthData(authRes.data);
    } catch (err) {
      console.error('Error loading OSIVault security data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSendEmailOTP = async (e) => {
    if (e) e.preventDefault();
    if (!otpEmail) return;
    setActionBanner({ type: 'info', message: `Dispatching 6-Digit Email OTP to '${otpEmail}'...` });
    try {
      const res = await ediApi.sendEmailOTP(otpEmail);
      if (res.data.status === 'success') {
        if (res.data.otp_code) setOtpCode(res.data.otp_code);
        setActionBanner({ type: 'success', message: `🎉 ${res.data.message}` });
        fetchOSIVaultData();
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'Failed to dispatch Email OTP.' });
    }
  };

  const handleVerifyEmailOTP = async (e) => {
    if (e) e.preventDefault();
    if (!otpEmail || !otpCode) return;
    setActionBanner({ type: 'info', message: `Verifying OTP '${otpCode}' for '${otpEmail}'...` });
    try {
      const res = await ediApi.verifyEmailOTP(otpEmail, otpCode);
      if (res.data.status === 'success') {
        setActionBanner({ type: 'success', message: `✅ ${res.data.message}` });
        fetchOSIVaultData();
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'OTP verification failed.' });
    }
  };

  const handleRegisterUserAuth = async (e) => {
    if (e) e.preventDefault();
    if (!regUsername || !otpEmail || !regPassword) return;
    setActionBanner({ type: 'info', message: `Registering account '${regUsername}' with osivault.auth...` });
    try {
      const res = await ediApi.registerUserAuth(regUsername, otpEmail, regPassword, otpCode);
      if (res.data.status === 'success') {
        setActionBanner({ type: 'success', message: res.data.message });
        fetchOSIVaultData();
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'User registration failed.' });
    }
  };

  useEffect(() => {
    fetchOSIVaultData();
  }, [auditTargetTable]);

  const handleBlindIndexSearch = async (e) => {
    if (e) e.preventDefault();
    if (!searchQuery) return;
    setActionBanner({ type: 'info', message: `Computing SearchHash('${searchQuery}') for blind index SQL query...` });
    try {
      const res = await ediApi.searchOSIVaultFieldsBlindIndex(searchQuery);
      setSearchResults(res.data);
      setActionBanner({ 
        type: 'success', 
        message: `Blind Index Search complete! Hash: ${res.data.blind_index_hash.substring(0, 16)}... Records Found: ${res.data.records_found}` 
      });
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'Blind index search failed.' });
    }
  };

  const handleRotateKeys = async () => {
    setActionBanner({ type: 'info', message: 'Executing DEK key rotation with rotate_dek()...' });
    try {
      const res = await ediApi.rotateOSIVaultFieldsKeys();
      if (res.data.status === 'success') {
        setActionBanner({ type: 'success', message: res.data.message });
        fetchOSIVaultData();
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'Key rotation failed.' });
    }
  };

  const handleVerifyChain = async () => {
    setActionBanner({ type: 'info', message: `Verifying SHA-256 HMAC audit chain for '${auditTargetTable}' table...` });
    try {
      const res = await ediApi.verifyOSIVaultAuditChain(auditTargetTable);
      setChainReport(res.data);
      if (res.data.is_intact) {
        setActionBanner({ type: 'success', message: res.data.message });
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'Chain verification failed.' });
    }
  };

  const handleCreateCheckpoint = async () => {
    setActionBanner({ type: 'info', message: `Generating signed anti-replacement checkpoint for '${auditTargetTable}' table...` });
    try {
      const res = await ediApi.createOSIVaultAuditCheckpoint(auditTargetTable);
      setCheckpointReport(res.data);
      if (res.data.is_valid) {
        setActionBanner({ type: 'success', message: res.data.message });
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'Checkpoint creation failed.' });
    }
  };

  const handleEncryptFile = async (filename) => {
    setActionBanner({ type: 'info', message: `Encrypting '${filename}' with OSIVault AES-256 cipher...` });
    try {
      const res = await ediApi.encryptFileOSIVault(filename);
      if (res.data.status === 'success' || res.data.status === 'info') {
        setActionBanner({ type: 'success', message: res.data.message });
        fetchOSIVaultData();
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'Encryption failed.' });
    }
  };

  const handleDecryptFile = async (e) => {
    if (e) e.preventDefault();
    if (!decryptFilename) return;
    setActionBanner({ type: 'info', message: `Authenticating Superuser '${decryptUser}' + YubiKey touch to decrypt '${decryptFilename}'...` });
    try {
      const res = await ediApi.decryptFileOSIVault(decryptFilename, decryptUser, decryptPass);
      if (res.data.status === 'success') {
        setDecryptResult(res.data);
        setActionBanner({ type: 'success', message: res.data.message });
        fetchOSIVaultData();
      } else {
        setActionBanner({ type: 'error', message: res.data.message });
      }
    } catch (err) {
      setActionBanner({ type: 'error', message: err.response?.data?.message || 'Decryption failed.' });
    }
  };

  return (
    <div className="space-y-6">
      {/* OSIVault Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-rose-950 to-emerald-950 text-white rounded-3xl p-6 shadow-xl border border-rose-500/30 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 rounded-full bg-rose-500/20 text-rose-300 text-xs font-black uppercase tracking-wider border border-rose-500/40 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-rose-300 animate-pulse" /> Full OSIVault Security Integration
              </span>
              <span className="text-xs text-emerald-300 font-mono font-bold">4 Active Modules</span>
            </div>
            <h1 className="text-2xl font-black tracking-tight mt-1.5 flex items-center gap-2">
              <ShieldCheck className="w-7 h-7 text-emerald-400 stroke-[2.5]" />
              OSIVault Security Core Module Testing Suite
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl leading-relaxed">
              Integrated testing environment for <code className="text-rose-300 font-mono font-bold">osivault.fields</code> (DB Field Encryption), <code className="text-rose-300 font-mono font-bold">osivault.audit</code> (Cryptographic Chained Logs), <code className="text-rose-300 font-mono font-bold">osivault.auth</code> (YubiKey MFA), and <code className="text-rose-300 font-mono font-bold">osivault.sftp</code> (Hardware-Gated File Viewer).
            </p>
          </div>

          <button
            onClick={fetchOSIVaultData}
            className="px-4 py-2.5 rounded-2xl bg-white/10 hover:bg-white/20 text-white font-extrabold text-xs flex items-center gap-2 transition-all cursor-pointer border border-white/20 shrink-0"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Security State
          </button>
        </div>

        {/* Module Status Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-6 border-t border-white/10 text-xs font-bold">
          <div className="bg-white/10 p-3 rounded-2xl border border-teal-400/30 flex items-center gap-2">
            <Database className="w-4 h-4 text-teal-400" />
            <div>
              <div className="text-[10px] text-slate-300 font-mono uppercase">DB Field Crypto</div>
              <div className="text-emerald-300 font-extrabold">osivault.fields</div>
            </div>
          </div>
          <div className="bg-white/5 p-3 rounded-2xl border border-white/10 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-rose-400" />
            <div>
              <div className="text-[10px] text-slate-400 font-mono uppercase">Keyed Chained Logs</div>
              <div className="text-emerald-300 font-extrabold">osivault.audit</div>
            </div>
          </div>
          <div className="bg-white/5 p-3 rounded-2xl border border-white/10 flex items-center gap-2">
            <Key className="w-4 h-4 text-pink-400" />
            <div>
              <div className="text-[10px] text-slate-400 font-mono uppercase">MFA & WebAuthn</div>
              <div className="text-emerald-300 font-extrabold">osivault.auth</div>
            </div>
          </div>
          <div className="bg-white/5 p-3 rounded-2xl border border-white/10 flex items-center gap-2">
            <Lock className="w-4 h-4 text-emerald-400" />
            <div>
              <div className="text-[10px] text-slate-400 font-mono uppercase">Superuser SFTP</div>
              <div className="text-emerald-300 font-extrabold">osivault.sftp</div>
            </div>
          </div>
        </div>
      </div>

      {/* Action Banner */}
      {actionBanner && (
        <div className={`p-4 rounded-2xl text-xs sm:text-sm font-bold flex items-center justify-between border shadow-sm ${
          actionBanner.type === 'error' ? 'bg-rose-50 text-rose-700 border-rose-200' :
          actionBanner.type === 'success' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' :
          'bg-pink-50 text-pink-800 border-pink-200'
        }`}>
          <span>{actionBanner.message}</span>
          <button onClick={() => setActionBanner(null)} className="text-xs font-bold underline cursor-pointer">Dismiss</button>
        </div>
      )}

      {/* Sub-Tab Navigation */}
      <div className="flex border-b border-rose-100 gap-2">
        <button
          onClick={() => setActiveSubTab('fields')}
          className={`px-4 py-3 text-xs font-black rounded-t-2xl transition-all cursor-pointer border-t border-x ${
            activeSubTab === 'fields' 
              ? 'bg-white text-teal-600 border-teal-200 border-b-white -mb-px shadow-xs' 
              : 'text-slate-500 hover:text-slate-800 bg-slate-50/50 border-transparent'
          }`}
        >
          🔒 osivault.fields (Blind Index Search & Envelope Encryption)
        </button>

        <button
          onClick={() => setActiveSubTab('audit')}
          className={`px-4 py-3 text-xs font-black rounded-t-2xl transition-all cursor-pointer border-t border-x ${
            activeSubTab === 'audit' 
              ? 'bg-white text-rose-600 border-rose-200 border-b-white -mb-px shadow-xs' 
              : 'text-slate-500 hover:text-slate-800 bg-slate-50/50 border-transparent'
          }`}
        >
          🛡️ osivault.audit (Tamper-Evident SHA-256 Chained Logs)
        </button>

        <button
          onClick={() => setActiveSubTab('auth')}
          className={`px-4 py-3 text-xs font-black rounded-t-2xl transition-all cursor-pointer border-t border-x ${
            activeSubTab === 'auth' 
              ? 'bg-white text-pink-600 border-pink-200 border-b-white -mb-px shadow-xs' 
              : 'text-slate-500 hover:text-slate-800 bg-slate-50/50 border-transparent'
          }`}
        >
          🔑 osivault.auth (Email OTP, MFA Studio & YubiKeys)
        </button>

        <button
          onClick={() => setActiveSubTab('sftp')}
          className={`px-4 py-3 text-xs font-black rounded-t-2xl transition-all cursor-pointer border-t border-x ${
            activeSubTab === 'sftp' 
              ? 'bg-white text-emerald-600 border-emerald-200 border-b-white -mb-px shadow-xs' 
              : 'text-slate-500 hover:text-slate-800 bg-slate-50/50 border-transparent'
          }`}
        >
          🔑 osivault.sftp Superusers & YubiKeys
        </button>
      </div>

      {/* Sub-Tab 1: osivault.fields Blind Index & Key Rotation Suite */}
      {activeSubTab === 'fields' && (
        <div className="space-y-6">
          {/* Action Header Banner */}
          <div className="saas-card rounded-3xl p-6 shadow-sm border-l-4 border-l-teal-500 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="saas-badge-green px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider flex items-center gap-1">
                  <Sparkles className="w-3.5 h-3.5 text-emerald-600 animate-spin" /> DEK Envelope & Blind Index Encryption
                </span>
              </div>
              <h3 className="font-black text-slate-800 text-xl mt-1.5 flex items-center gap-2">
                <Database className="w-5 h-5 text-teal-600" /> osivault.fields Security Engine
              </h3>
              <p className="text-xs text-slate-500">Field-level AES-256-GCM envelope encryption at rest with <code className="text-teal-700 font-mono font-bold">SearchHash()</code> blind index for O(1) encrypted column search.</p>
            </div>

            <div className="flex flex-wrap items-center gap-3 shrink-0">
              <button
                onClick={handleRotateKeys}
                className="saas-btn-primary px-4 py-2.5 rounded-2xl font-black text-xs flex items-center gap-2 transition-all cursor-pointer border border-rose-300 shadow-md"
              >
                <RotateCw className="w-4 h-4 text-white" /> Rotate DEK Keys (rotate_dek)
              </button>
            </div>
          </div>

          {/* Blind Index Search Sandbox */}
          <div className="saas-card rounded-3xl p-6 space-y-4 shadow-sm border-t-2 border-t-teal-500">
            <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
              <Search className="w-4 h-4 text-teal-600" /> SearchHash() Blind Index Search Sandbox
            </h4>
            <form onSubmit={handleBlindIndexSearch} className="flex flex-col sm:flex-row items-center gap-3">
              <input
                type="text"
                placeholder="Enter Policy Number to search (e.g. Z30366883 or LAM839001006)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-teal-500 font-mono"
              />
              <button
                type="submit"
                className="px-5 py-2.5 rounded-xl bg-teal-600 hover:bg-teal-700 text-white font-black text-xs flex items-center gap-2 transition-all cursor-pointer shadow-sm shrink-0"
              >
                <Search className="w-4 h-4 text-white" /> Run Blind Index Query
              </button>
            </form>

            {searchResults && (
              <div className="bg-slate-900 text-emerald-400 rounded-2xl p-4 space-y-2 text-xs font-mono border border-slate-800 shadow-inner">
                <div className="flex items-center justify-between text-slate-400 font-sans font-bold border-b border-slate-800 pb-2">
                  <span>Deterministic Search Hash:</span>
                  <span className="text-emerald-400 font-mono">{searchResults.blind_index_hash}</span>
                </div>
                <div className="text-slate-300 font-sans">
                  Found <strong className="text-emerald-400">{searchResults.records_found}</strong> encrypted database records matching blind index!
                </div>
              </div>
            )}
          </div>

          {/* EncryptedCharField & EncryptedJSONField Inspection Table */}
          <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
            <div className="px-6 py-4 bg-teal-50/50 border-b border-teal-100 flex items-center justify-between">
              <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                <Database className="w-4 h-4 text-teal-600" /> Database SQL Envelope vs ORM Decrypted Property
              </h4>
              <span className="saas-badge-green text-xs font-bold px-3 py-1 rounded-full">
                EncryptedCharField & EncryptedJSONField
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-700">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-extrabold uppercase tracking-wider">
                  <tr>
                    <th className="px-6 py-4">Member Name & ID</th>
                    <th className="px-6 py-4">Django ORM Decrypted Value</th>
                    <th className="px-6 py-4">Raw Database SQL Value (At-Rest Ciphertext)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  {fieldsData.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="px-6 py-8 text-center text-slate-400 font-sans font-medium">
                        No encrypted member records found. Upload an EDI file to test `osivault.fields`!
                      </td>
                    </tr>
                  ) : (
                    fieldsData.map((row) => (
                      <tr key={row.id} className="hover:bg-teal-50/30 transition-colors">
                        <td className="px-6 py-4 font-bold text-slate-800 font-sans">
                          {row.first_name} {row.last_name}
                          <div className="text-[11px] font-mono text-teal-600">{row.member_id}</div>
                        </td>
                        <td className="px-6 py-4 font-sans space-y-1">
                          <div className="text-slate-800 font-bold">Policy: <span className="font-mono text-rose-600">{row.orm_decrypted.policy_number}</span></div>
                          <div className="text-slate-600 text-[11px]">Address: {row.orm_decrypted.address}, {row.orm_decrypted.city}</div>
                          <div className="text-slate-500 text-[11px]">DOB: {row.orm_decrypted.dob}</div>
                        </td>
                        <td className="px-6 py-4 max-w-md">
                          <div className="bg-slate-900 text-emerald-400 p-2.5 rounded-xl text-[10px] break-all border border-slate-800 shadow-inner">
                            {row.raw_db_encrypted.policy_number || 'OSV1$AES-256-GCM$default$eyJ2...'}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab 2: osivault.audit Cryptographic Verification & Checkpoint Suite */}
      {activeSubTab === 'audit' && (
        <div className="space-y-6">
          {/* Action Header Banner */}
          <div className="saas-card rounded-3xl p-6 shadow-sm border-l-4 border-l-rose-500 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="saas-badge-pink px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider flex items-center gap-1">
                  <Sparkles className="w-3.5 h-3.5 text-rose-500 animate-spin" /> Keyed HMAC SHA-256 Chain Verification
                </span>
              </div>
              <h3 className="font-black text-slate-800 text-xl mt-1.5 flex items-center gap-2">
                <Cpu className="w-5 h-5 text-rose-500" /> osivault.audit Tamper-Evident Engine
              </h3>
              <p className="text-xs text-slate-500">Every audit entry calculates a cryptographic SHA-256 HMAC entry hash chained to the previous entry hash.</p>
            </div>

            <div className="flex flex-wrap items-center gap-3 shrink-0">
              <button
                onClick={handleVerifyChain}
                className="saas-btn-primary px-4 py-2.5 rounded-2xl font-black text-xs flex items-center gap-2 transition-all cursor-pointer border border-rose-300 shadow-md"
              >
                <ShieldCheck className="w-4 h-4 text-white" /> Verify Cryptographic Chain
              </button>

              <button
                onClick={handleCreateCheckpoint}
                className="px-4 py-2.5 rounded-2xl bg-emerald-600 hover:bg-emerald-700 text-white font-black text-xs flex items-center gap-2 transition-all cursor-pointer shadow-md border border-emerald-500"
              >
                <GitCommit className="w-4 h-4 text-white" /> Generate Anti-Replacement Checkpoint
              </button>
            </div>
          </div>

          {/* Cryptographic Reports Summary Grid */}
          {(chainReport || checkpointReport) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {chainReport && (
                <div className={`saas-card rounded-3xl p-5 border-2 shadow-sm ${chainReport.is_intact ? 'border-emerald-300 bg-emerald-50/40' : 'border-rose-300 bg-rose-50/40'}`}>
                  <div className="flex items-center justify-between">
                    <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                      <ShieldCheck className={`w-4 h-4 ${chainReport.is_intact ? 'text-emerald-600' : 'text-rose-600'}`} />
                      Audit Chain Integrity Report
                    </h4>
                    <span className={`px-3 py-1 rounded-full text-xs font-black ${chainReport.is_intact ? 'saas-badge-green' : 'saas-badge-pink'}`}>
                      {chainReport.is_intact ? '100% INTACT & TAMPER-FREE' : 'CHAIN CORRUPTED'}
                    </span>
                  </div>
                  <div className="mt-3 text-xs space-y-1 font-mono text-slate-600">
                    <div>Table: <strong className="text-slate-800">{chainReport.table_name}</strong></div>
                    <div>Total Cryptographic Entries: <strong className="text-slate-800">{chainReport.total_count}</strong></div>
                    <div>Current Key Hash Count: <strong className="text-slate-800">{chainReport.current_key_count}</strong></div>
                  </div>
                </div>
              )}

              {checkpointReport && (
                <div className={`saas-card rounded-3xl p-5 border-2 shadow-sm ${checkpointReport.is_valid ? 'border-emerald-300 bg-emerald-50/40' : 'border-rose-300 bg-rose-50/40'}`}>
                  <div className="flex items-center justify-between">
                    <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                      <GitCommit className={`w-4 h-4 ${checkpointReport.is_valid ? 'text-emerald-600' : 'text-rose-600'}`} />
                      Signed Checkpoint Anti-Replacement Report
                    </h4>
                    <span className={`px-3 py-1 rounded-full text-xs font-black ${checkpointReport.is_valid ? 'saas-badge-green' : 'saas-badge-pink'}`}>
                      {checkpointReport.is_valid ? 'CHECKPOINT VALIDATED' : 'INVALID CHECKPOINT'}
                    </span>
                  </div>
                  <div className="mt-3 text-xs space-y-1 font-mono text-slate-600">
                    <div>Checkpoint ID: <strong className="text-slate-800">#{checkpointReport.checkpoint_id}</strong></div>
                    <div>Verified Table Rows: <strong className="text-slate-800">{checkpointReport.row_count} rows</strong></div>
                    <div className="truncate">Checkpoint Hash: <strong className="text-emerald-700">{checkpointReport.checkpoint_hash}</strong></div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Audit Logs Table */}
          <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
            <div className="px-6 py-4 bg-rose-50/50 border-b border-rose-100 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <h4 className="font-black text-slate-800 text-sm">Target Audit Log Model Table:</h4>
                <div className="flex items-center gap-1.5 bg-white p-1 rounded-xl border border-rose-200">
                  <button
                    onClick={() => setAuditTargetTable('document')}
                    className={`px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                      auditTargetTable === 'document' ? 'bg-rose-500 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    EDIDocumentAuditLog
                  </button>
                  <button
                    onClick={() => setAuditTargetTable('member')}
                    className={`px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                      auditTargetTable === 'member' ? 'bg-rose-500 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    EDIMemberAuditLog
                  </button>
                  <button
                    onClick={() => setAuditTargetTable('central')}
                    className={`px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                      auditTargetTable === 'central' ? 'bg-rose-500 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    SaaSCompanyCentralAuditLog
                  </button>
                </div>
              </div>
              <span className="saas-badge-pink text-xs font-bold px-3 py-1 rounded-full">
                osivault.audit Immutability Guard Active
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-700">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-extrabold uppercase tracking-wider">
                  <tr>
                    <th className="px-6 py-3.5">ID & Timestamp</th>
                    <th className="px-6 py-3.5">Actor & Tenant</th>
                    <th className="px-6 py-3.5">Resource & Action</th>
                    <th className="px-6 py-3.5 font-mono">Chained Previous Hash</th>
                    <th className="px-6 py-3.5 font-mono text-right">Cryptographic Entry Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-xs">
                  {auditLogs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-slate-400 font-sans font-medium">
                        No cryptographic audit logs in table <code className="text-rose-600 font-mono">{auditTargetTable}</code> yet. Upload an EDI file to trigger automatic signals!
                      </td>
                    </tr>
                  ) : (
                    auditLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-rose-50/30 transition-colors">
                        <td className="px-6 py-4 font-bold text-slate-800 font-sans">
                          #{log.id}
                          <div className="text-[11px] font-mono text-slate-400 font-normal">{log.timestamp}</div>
                        </td>
                        <td className="px-6 py-4 font-sans space-y-0.5">
                          <div className="font-extrabold text-slate-800">{log.actor}</div>
                          <div className="text-[11px] text-emerald-700 font-mono">{log.tenant}</div>
                        </td>
                        <td className="px-6 py-4 font-sans space-y-1">
                          <span className="saas-badge-pink inline-block px-2.5 py-0.5 rounded-md text-[11px] font-bold">
                            {log.action}
                          </span>
                          <div className="text-[11px] text-slate-500">{log.resource_type} (ID: {log.resource_id})</div>
                        </td>
                        <td className="px-6 py-4 text-slate-400 truncate max-w-xs">
                          {log.previous_hash || '(Genesis Entry)'}
                        </td>
                        <td className="px-6 py-4 text-right font-bold text-emerald-700 truncate max-w-xs">
                          {log.entry_hash}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab: osivault.auth Email OTP, User MFA & WebAuthn YubiKey Suite */}
      {activeSubTab === 'auth' && (
        <div className="space-y-6">
          {/* Action Header Banner */}
          <div className="saas-card rounded-3xl p-6 shadow-sm border-l-4 border-l-pink-500 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="saas-badge-pink px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider flex items-center gap-1">
                  <Key className="w-3.5 h-3.5 text-pink-600" /> MFA & Hardware WebAuthn Engine
                </span>
                <span className="text-xs text-slate-500 font-mono font-bold">
                  {authData?.total_users || 0} Registered Users | {authData?.total_otps_dispatched || 0} OTPs Dispatched
                </span>
              </div>
              <h3 className="font-black text-slate-800 text-xl mt-1.5 flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-pink-600" /> osivault.auth Authentication Core
              </h3>
              <p className="text-xs text-slate-500">Built-in Email OTP verification, user session management, RS256 JWT tokens, TOTP secrets, and WebAuthn FIDO2 YubiKey credentials.</p>
            </div>

            <div className="flex flex-wrap items-center gap-3 shrink-0">
              <button
                onClick={onOpenAuthModal}
                className="saas-btn-primary px-4 py-2.5 rounded-2xl font-black text-xs flex items-center gap-2 transition-all cursor-pointer border border-rose-300 shadow-md"
              >
                <Key className="w-4 h-4 text-white animate-pulse" /> Launch osivault.auth Gated Pop-up Portal
              </button>
            </div>
          </div>

          {/* Interactive Testing Studio Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Studio 1: Email OTP Dispatch & Verification */}
            <div className="saas-card rounded-3xl p-6 space-y-4 shadow-sm border-t-2 border-t-pink-500">
              <div className="flex items-center justify-between border-b border-pink-100 pb-3">
                <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                  <Key className="w-4 h-4 text-pink-600" /> Email OTP Verification Studio
                </h4>
                <span className="saas-badge-pink text-[10px] font-bold px-2 py-0.5 rounded">10-Min Expiry</span>
              </div>

              <form onSubmit={handleSendEmailOTP} className="space-y-3">
                <div>
                  <label className="text-[11px] font-extrabold text-slate-600 uppercase tracking-wider block mb-1">Target User Email Address</label>
                  <input
                    type="email"
                    value={otpEmail}
                    onChange={(e) => setOtpEmail(e.target.value)}
                    placeholder="Enter email (e.g. developer@onesmarter.com)..."
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-2 text-xs font-mono text-slate-800 focus:outline-none focus:border-pink-500"
                    required
                  />
                </div>

                <div className="flex gap-2">
                  <button
                    type="submit"
                    className="flex-1 px-4 py-2.5 rounded-xl bg-pink-600 hover:bg-pink-700 text-white font-black text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer shadow-sm"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-white" /> Dispatch 6-Digit OTP
                  </button>

                  <button
                    type="button"
                    onClick={handleVerifyEmailOTP}
                    className="flex-1 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-black text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer shadow-sm"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 text-white" /> Verify OTP Code
                  </button>
                </div>
              </form>

              <div>
                <label className="text-[11px] font-extrabold text-slate-600 uppercase tracking-wider block mb-1">6-Digit Verification Code</label>
                <input
                  type="text"
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value)}
                  placeholder="Enter 6-digit OTP code (e.g. 127078)..."
                  className="w-full bg-pink-50/50 border border-pink-200 rounded-xl px-4 py-2 text-xs font-mono font-bold text-pink-700 focus:outline-none focus:border-pink-500"
                />
              </div>
            </div>

            {/* Studio 2: User Account Registration */}
            <div className="saas-card rounded-3xl p-6 space-y-4 shadow-sm border-t-2 border-t-emerald-500">
              <div className="flex items-center justify-between border-b border-emerald-100 pb-3">
                <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-600" /> User Account Registration Studio
                </h4>
                <span className="saas-badge-green text-[10px] font-bold px-2 py-0.5 rounded">Email OTP Gated</span>
              </div>

              <form onSubmit={handleRegisterUserAuth} className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[11px] font-extrabold text-slate-600 uppercase tracking-wider block mb-1">Username</label>
                    <input
                      type="text"
                      value={regUsername}
                      onChange={(e) => setRegUsername(e.target.value)}
                      placeholder="Username..."
                      className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-emerald-500"
                      required
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-extrabold text-slate-600 uppercase tracking-wider block mb-1">Password</label>
                    <input
                      type="password"
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      placeholder="Password..."
                      className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-emerald-500"
                      required
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  className="w-full px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-black text-xs flex items-center justify-center gap-2 transition-all cursor-pointer shadow-sm"
                >
                  <CheckCircle2 className="w-4 h-4 text-white" /> Register User Account with osivault.auth
                </button>
              </form>
            </div>
          </div>

          {/* Registered Users & MFA Status Table */}
          <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
            <div className="px-6 py-4 bg-pink-50/50 border-b border-pink-100 flex items-center justify-between">
              <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-pink-600" /> Registered SaaS Accounts & MFA Security Profiles ({authData?.users?.length || 0})
              </h4>
              <span className="saas-badge-pink text-xs font-bold px-3 py-1 rounded-full">
                osivault_auth User Profile
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-700">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-extrabold uppercase tracking-wider">
                  <tr>
                    <th className="px-6 py-3.5">ID & Username</th>
                    <th className="px-6 py-3.5">Registered Email</th>
                    <th className="px-6 py-3.5">Email OTP Status</th>
                    <th className="px-6 py-3.5">MFA Status</th>
                    <th className="px-6 py-3.5 text-right">Registered At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {(!authData?.users || authData.users.length === 0) ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-slate-400 font-medium">
                        No registered users found in osivault_auth tables. Use the studio above to register an account!
                      </td>
                    </tr>
                  ) : (
                    authData.users.map((u) => (
                      <tr key={u.id} className="hover:bg-pink-50/30 transition-colors">
                        <td className="px-6 py-4 font-black text-slate-800">
                          #{u.id} {u.username}
                        </td>
                        <td className="px-6 py-4 font-bold text-slate-700 font-mono">
                          {u.email}
                        </td>
                        <td className="px-6 py-4">
                          {u.mfa_profile?.email_verified ? (
                            <span className="saas-badge-green px-3 py-1 rounded-xl text-xs font-bold inline-flex items-center gap-1.5">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Verified
                            </span>
                          ) : (
                            <span className="bg-amber-100 text-amber-800 px-3 py-1 rounded-xl text-xs font-bold inline-flex items-center gap-1.5">
                              Pending
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <span className="saas-badge-pink px-3 py-1 rounded-xl text-xs font-bold inline-flex items-center gap-1.5">
                            <Key className="w-3.5 h-3.5 text-pink-600" /> {u.mfa_profile?.preferred_method || 'WEBAUTHN'}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-right font-mono text-slate-500">
                          {u.date_joined}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Dispatched Email OTP Verification Logs */}
          <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
            <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                <Key className="w-4 h-4 text-pink-600" /> Dispatched Email OTP Verification History ({authData?.recent_otps?.length || 0})
              </h4>
              <span className="saas-badge-green text-xs font-bold px-3 py-1 rounded-full">
                osivault_email_otp_verification
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-700">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-extrabold uppercase tracking-wider">
                  <tr>
                    <th className="px-6 py-3.5">Target Email</th>
                    <th className="px-6 py-3.5 font-mono">6-Digit OTP Code</th>
                    <th className="px-6 py-3.5">Purpose</th>
                    <th className="px-6 py-3.5">Verification Status</th>
                    <th className="px-6 py-3.5 text-right font-mono">Expires At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-xs">
                  {(!authData?.recent_otps || authData.recent_otps.length === 0) ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-slate-400 font-sans font-medium">
                        No OTPs dispatched yet.
                      </td>
                    </tr>
                  ) : (
                    authData.recent_otps.map((o) => (
                      <tr key={o.id} className="hover:bg-slate-50 transition-colors">
                        <td className="px-6 py-4 font-bold text-slate-800 font-sans">
                          {o.email}
                        </td>
                        <td className="px-6 py-4 font-black text-pink-600">
                          {o.otp_code}
                        </td>
                        <td className="px-6 py-4 font-sans text-slate-600">
                          {o.purpose}
                        </td>
                        <td className="px-6 py-4 font-sans">
                          {o.is_verified ? (
                            <span className="saas-badge-green px-2.5 py-0.5 rounded text-[11px] font-bold">Verified</span>
                          ) : (
                            <span className="bg-slate-100 text-slate-600 px-2.5 py-0.5 rounded text-[11px] font-bold">Unverified ({o.attempts} attempts)</span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-right text-slate-500">
                          {o.expires_at}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab 3: osivault.sftp Superusers & Terminal Viewer */}
      {activeSubTab === 'sftp' && (
        <div className="space-y-6">
          {/* Hardware-Gated File Decrypt Sandbox */}
          <div className="saas-card rounded-3xl p-6 space-y-4 border-l-4 border-l-emerald-500 shadow-sm">
            <div className="flex items-center justify-between border-b border-emerald-100 pb-3">
              <div>
                <h3 className="font-extrabold text-slate-800 text-base flex items-center gap-2">
                  <Key className="w-5 h-5 text-emerald-600" /> Hardware-Gated File Decryption & View Sandbox
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Select an encrypted ciphertext file in <code className="text-emerald-700 font-mono font-bold">D:\Transfers\Server_Directory</code> to authenticate Superuser + YubiKey contact touch.
                </p>
              </div>
              <span className="saas-badge-green text-xs font-bold px-3 py-1 rounded-full">
                osivault.sftp Decrypt Engine
              </span>
            </div>

            <form onSubmit={handleDecryptFile} className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-[11px] font-extrabold text-slate-600 uppercase tracking-wider block mb-1">Target Encrypted File</label>
                <select
                  value={decryptFilename}
                  onChange={(e) => setDecryptFilename(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-mono text-slate-800 focus:outline-none focus:border-emerald-500"
                >
                  <option value="">-- Select File in Server Directory --</option>
                  {directoryFiles.map((f, idx) => (
                    <option key={idx} value={f.filename}>
                      {f.filename} ({f.is_encrypted ? '🔒 OSIV Ciphertext' : '📄 Plaintext'})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[11px] font-extrabold text-slate-600 uppercase tracking-wider block mb-1">Superuser Username</label>
                <input
                  type="text"
                  value={decryptUser}
                  onChange={(e) => setDecryptUser(e.target.value)}
                  placeholder="Superuser username..."
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex items-end gap-2">
                <div className="flex-1">
                  <label className="text-[11px] font-extrabold text-slate-600 uppercase tracking-wider block mb-1">Superuser Password</label>
                  <input
                    type="password"
                    value={decryptPass}
                    onChange={(e) => setDecryptPass(e.target.value)}
                    placeholder="Password..."
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-black text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-sm shrink-0"
                >
                  <Key className="w-4 h-4 text-white" /> Decrypt File
                </button>
              </div>
            </form>

            {decryptResult && (
              <div className="bg-slate-900 text-slate-100 p-4 rounded-2xl space-y-2 text-xs font-mono border border-slate-800 shadow-inner mt-4">
                <div className="text-emerald-400 font-bold flex items-center justify-between font-sans">
                  <span>🔑 Decrypted Plaintext In-Memory Preview ({decryptResult.filename})</span>
                  <span className="saas-badge-green px-2 py-0.5 rounded text-[10px]">SHA-256 Verified</span>
                </div>
                <div className="text-[11px] text-cyan-300">SHA-256 Checksum: {decryptResult.sha256_hash}</div>
                <pre className="text-[11px] text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap bg-slate-950 p-3 rounded-xl border border-slate-800">
                  {decryptResult.preview}
                </pre>
              </div>
            )}
          </div>

          {/* Terminal Command Instructions */}
          <div className="saas-card rounded-3xl p-6 space-y-4 border-l-4 border-l-rose-500 shadow-sm">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-rose-500" />
              <h3 className="font-extrabold text-slate-800 text-base">OSIVault Terminal Superuser Commands</h3>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
              {/* Command 1: Superuser Registration */}
              <div className="bg-slate-900 text-slate-100 rounded-2xl p-4 space-y-2 font-mono border border-slate-800">
                <div className="text-rose-400 font-bold flex items-center justify-between font-sans">
                  <span>1. SaaS Superuser Registration Wizard (Max 3)</span>
                  <span className="saas-badge-pink px-2 py-0.5 rounded text-[10px]">CLI Command</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-xl text-emerald-400 text-[11px] font-bold select-all">
                  python manage.py create_sftp_superuser
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  Prompts for Username, Email, Password, and registers 2 mandatory hardware YubiKeys (Primary + Backup slot).
                </p>
              </div>

              {/* Command 2: Hardware-Gated Notepad Viewer */}
              <div className="bg-slate-900 text-slate-100 rounded-2xl p-4 space-y-2 font-mono border border-slate-800">
                <div className="text-emerald-400 font-bold flex items-center justify-between font-sans">
                  <span>2. Hardware-Gated File Viewer</span>
                  <span className="saas-badge-green px-2 py-0.5 rounded text-[10px]">CLI Viewer</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-xl text-cyan-300 text-[11px] font-bold select-all">
                  python manage.py sftp_view_file D:\Transfers\Server_Directory\filename.TXT
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  Authenticates Superuser + YubiKey touch, decrypts file temporarily in Notepad, and auto re-encrypts upon closing Notepad.
                </p>
              </div>
            </div>
          </div>

          {/* Registered SFTP Superusers Table */}
          <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
            <div className="px-6 py-4 bg-rose-50/50 border-b border-rose-100 flex items-center justify-between">
              <h4 className="font-black text-slate-800 text-sm flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-rose-500" /> Active SFTP Superusers ({superusers.length} / 3 Allowed)
              </h4>
              <span className="saas-badge-pink text-xs font-bold px-3 py-1 rounded-full">
                osivault.sftp Security Model
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-700">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-extrabold uppercase tracking-wider">
                  <tr>
                    <th className="px-6 py-3.5">Superuser Account</th>
                    <th className="px-6 py-3.5">Email & Mobile</th>
                    <th className="px-6 py-3.5">Slot 1: Default Primary YubiKey</th>
                    <th className="px-6 py-3.5">Slot 2: Backup YubiKey</th>
                    <th className="px-6 py-3.5 text-right">Created At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {superusers.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-slate-400 font-medium">
                        No SFTP Superusers registered yet. Run <code className="text-rose-600 font-mono font-bold">python manage.py create_sftp_superuser</code> in terminal!
                      </td>
                    </tr>
                  ) : (
                    superusers.map((u) => {
                      const primaryKey = u.yubikeys.find(k => k.slot_type === 'PRIMARY');
                      const backupKey = u.yubikeys.find(k => k.slot_type === 'BACKUP');
                      return (
                        <tr key={u.id} className="hover:bg-rose-50/30 transition-colors">
                          <td className="px-6 py-4 font-black text-slate-800">
                            {u.username}
                          </td>
                          <td className="px-6 py-4 space-y-0.5 text-slate-600">
                            <div className="font-bold text-slate-800">{u.email}</div>
                            <div className="text-[11px] font-mono text-slate-400">{u.mobile_number}</div>
                          </td>
                          <td className="px-6 py-4">
                            {primaryKey ? (
                              <span className="saas-badge-green px-3 py-1 rounded-xl text-xs font-bold inline-flex items-center gap-1.5">
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> {primaryKey.key_label}
                              </span>
                            ) : (
                              <span className="text-slate-400 font-mono">Not Registered</span>
                            )}
                          </td>
                          <td className="px-6 py-4">
                            {backupKey ? (
                              <span className="saas-badge-pink px-3 py-1 rounded-xl text-xs font-bold inline-flex items-center gap-1.5">
                                <Key className="w-3.5 h-3.5 text-rose-500" /> {backupKey.key_label}
                              </span>
                            ) : (
                              <span className="text-slate-400 font-mono">Not Registered</span>
                            )}
                          </td>
                          <td className="px-6 py-4 text-right font-mono text-slate-500">
                            {u.created_at}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OSIVaultSecurityView;
