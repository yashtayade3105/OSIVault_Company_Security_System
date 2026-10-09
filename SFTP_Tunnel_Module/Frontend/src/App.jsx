import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import EDIUploadModal from './components/EDIUploadModal';
import OSIVaultAuthModal from './components/OSIVaultAuthModal';
import DashboardView from './pages/DashboardView';
import UploadVaultView from './pages/UploadVaultView';
import MemberRecordsView from './pages/MemberRecordsView';
import ServerDirectoryView from './pages/ServerDirectoryView';
import OSIVaultSecurityView from './pages/OSIVaultSecurityView';
import { ediApi } from './services/api';
import { History, ShieldCheck, Sparkles } from 'lucide-react';

function App() {
  const [activeTab, setActiveTab] = useState('osivault');
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(true);

  const [stats, setStats] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [members, setMembers] = useState([]);
  const [directoryData, setDirectoryData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [statsRes, docsRes, membersRes, dirRes] = await Promise.all([
        ediApi.getDashboardStats().catch(() => ({ data: { status: 'success', data: null } })),
        ediApi.getDocuments().catch(() => ({ data: { results: [] } })),
        ediApi.getMembers().catch(() => ({ data: { results: [] } })),
        ediApi.getServerDirectoryFiles().catch(() => ({ data: { results: [] } })),
      ]);

      if (statsRes.data?.data) setStats(statsRes.data.data);
      if (docsRes.data?.results) setDocuments(docsRes.data.results);
      if (membersRes.data?.results) setMembers(membersRes.data.results);
      if (dirRes.data) setDirectoryData(dirRes.data);
    } catch (err) {
      console.error('Error fetching EDI API data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const defaultDocuments = [
    { id: 1, file_name: 'AHH_ABC_Elig_Full_251231103923.TXT', file_type: '834_BENEFIT_ENROLLMENT', interchange_control_number: '000002985', total_records_parsed: 4180, file_size: 1809602, is_encrypted_on_disk: false, status: 'STORED_PLAINTEXT' },
    { id: 2, file_name: 'AHH_ABC_Elig_Full_260130103923.TXT', file_type: '834_BENEFIT_ENROLLMENT', interchange_control_number: '000002986', total_records_parsed: 4180, file_size: 1809602, is_encrypted_on_disk: false, status: 'STORED_PLAINTEXT' },
  ];

  const defaultMembers = [
    { id: 1, member_id: '001509279', policy_number: 'LAM839001006', first_name: 'GLENN', last_name: 'O LEARY', full_name: 'GLENN O LEARY', dob: '1961-09-14', gender: 'M', city: 'ENGLEWOOD', state: 'FL', zip_code: '34224', coverage_plan: 'HLT - FAM' },
    { id: 2, member_id: '001568500', policy_number: 'LAM839001007', first_name: 'STEPHEN', last_name: 'MOORE', full_name: 'STEPHEN MOORE', dob: '1972-04-10', gender: 'M', city: 'FORT LAUDERDALE', state: 'FL', zip_code: '33301', coverage_plan: 'HLT - FAM' },
  ];

  const activeDocs = (documents && documents.length > 0) ? documents : defaultDocuments;
  const activeMembers = (members && members.length > 0) ? members : defaultMembers;

  return (
    <div className="flex min-h-screen font-sans selection:bg-rose-400 selection:text-white">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        <Header 
          activeTab={activeTab} 
          onOpenUploadModal={() => setIsUploadModalOpen(true)}
          onOpenAuthModal={() => setIsAuthModalOpen(true)}
        />

        <EDIUploadModal
          isOpen={isUploadModalOpen}
          onClose={() => setIsUploadModalOpen(false)}
          onUploadSuccess={() => {
            fetchData();
            setIsUploadModalOpen(false);
          }}
        />

        <OSIVaultAuthModal
          isOpen={isAuthModalOpen}
          onClose={() => setIsAuthModalOpen(false)}
          onAuthSuccess={() => {
            fetchData();
          }}
        />

        <main className="p-6 flex-1 max-w-7xl w-full mx-auto">
          {activeTab === 'dashboard' && (
            <DashboardView 
              stats={stats} 
              onNavigate={setActiveTab} 
            />
          )}

          {activeTab === 'osivault' && (
            <OSIVaultSecurityView onOpenAuthModal={() => setIsAuthModalOpen(true)} />
          )}

          {activeTab === 'upload' && (
            <UploadVaultView 
              documents={activeDocs} 
              onOpenUploadModal={() => setIsUploadModalOpen(true)}
              onSelectDocument={() => setActiveTab('members')}
            />
          )}

          {activeTab === 'members' && (
            <MemberRecordsView 
              members={activeMembers} 
            />
          )}

          {activeTab === 'directory' && (
            <ServerDirectoryView 
              directoryData={directoryData} 
              onRefresh={fetchData}
            />
          )}

          {activeTab === 'audit' && (
            <div className="saas-card border-l-4 border-l-rose-500 rounded-3xl p-6 shadow-sm space-y-5">
              <div>
                <div className="flex items-center gap-2">
                  <span className="saas-badge-pink px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-rose-500 animate-spin" /> Audit Trail Log
                  </span>
                </div>
                <h3 className="font-black text-slate-800 text-xl mt-1.5 flex items-center gap-2">
                  <History className="w-5 h-5 text-rose-500" /> EDI Transfer Audit Trail & Tamper Log
                </h3>
                <p className="text-xs text-slate-500">Automated event logging with SHA-256 cryptographic verification</p>
              </div>

              <div className="space-y-3">
                <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 text-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-2 shadow-xs">
                  <span className="saas-badge-pink text-xs font-extrabold px-3 py-1 rounded-xl">STORE_SERVER_DIRECTORY</span>
                  <span className="text-slate-800 font-mono">Plaintext file written to D:\Transfers\Server_Directory</span>
                  <span className="font-mono text-slate-400 font-bold">Just now</span>
                </div>
                <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 text-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-2 shadow-xs">
                  <span className="saas-badge-green text-xs font-extrabold px-3 py-1 rounded-xl">PARSE_DB_SYNC</span>
                  <span className="text-slate-800 font-mono">Parsed member records into DB (osivault.fields encrypted)</span>
                  <span className="font-mono text-slate-400 font-bold">2 min ago</span>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
