import React, { useState } from 'react';
import { Search, Users, Shield, MapPin, Calendar, Briefcase, Sparkles } from 'lucide-react';

const MemberRecordsView = ({ members }) => {
  const [search, setSearch] = useState('');

  const filteredMembers = members.filter(m => 
    search === '' ||
    m.first_name?.toLowerCase().includes(search.toLowerCase()) ||
    m.last_name?.toLowerCase().includes(search.toLowerCase()) ||
    m.member_id?.toLowerCase().includes(search.toLowerCase()) ||
    m.city?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-5">
      {/* Search Bar & Header */}
      <div className="saas-card rounded-3xl p-5 flex flex-col md:flex-row items-center justify-between gap-4 shadow-sm border-l-4 border-l-emerald-500">
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
          <input 
            type="text"
            placeholder="Search member by name, ID, city..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-rose-400 focus:ring-2 focus:ring-rose-400/20 font-medium"
          />
        </div>
        <div className="text-xs text-slate-600 font-bold bg-slate-50 px-4 py-2 rounded-xl border border-slate-200">
          Showing <strong className="text-emerald-700 font-black">{filteredMembers.length}</strong> Parsed Subscriber Records
        </div>
      </div>

      {/* Members Table */}
      <div className="saas-card rounded-3xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-700">
            <thead className="bg-rose-50/50 border-b border-rose-100 text-slate-600 font-extrabold uppercase tracking-wider">
              <tr>
                <th className="px-6 py-4">Member Name & ID</th>
                <th className="px-6 py-4">Demographics</th>
                <th className="px-6 py-4">Address</th>
                <th className="px-6 py-4">Health Plan Coverage</th>
                <th className="px-6 py-4 font-mono text-right">Policy #</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredMembers.map((m) => (
                <tr key={m.id} className="hover:bg-rose-50/30 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-rose-500 to-pink-400 text-white flex items-center justify-center font-black text-xs shadow-xs shrink-0">
                        {m.first_name?.[0] || m.full_name?.[0] || 'M'}{m.last_name?.[0] || ''}
                      </div>
                      <div>
                        <div className="font-extrabold text-slate-800 text-xs">{m.full_name || m.member_id}</div>
                        <div className="text-[11px] font-mono text-rose-600 font-bold">{m.member_id}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 space-y-0.5 text-slate-600">
                    <div>DOB: {m.dob || '1985-01-01'}</div>
                    <div className="text-[11px] text-slate-500">Gender: {m.gender || 'M'}</div>
                  </td>
                  <td className="px-6 py-4 space-y-0.5 text-slate-600">
                    <div className="flex items-center gap-1.5 text-slate-800 font-medium">
                      <MapPin className="w-3.5 h-3.5 text-emerald-600" /> {m.city || 'Tampa'}, {m.state || 'FL'}
                    </div>
                    <div className="text-[11px] text-slate-500 truncate max-w-xs">{m.address || '2046 Willow Ave'}</div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="saas-badge-green px-3 py-1 font-extrabold text-[11px] rounded-xl">
                      {m.coverage_plan || 'HLT - FAM'}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right font-mono text-rose-600 font-extrabold">
                    {m.policy_number || 'LAM839001006'}
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

export default MemberRecordsView;
