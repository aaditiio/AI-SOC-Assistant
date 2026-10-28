import React, { useState, useEffect } from 'react';
import {
  Fingerprint,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  UserCheck,
  UserX,
  KeyRound,
  RotateCcw,
  AlertTriangle,
  Lock,
  Unlock,
  CheckCircle2,
  Globe,
  Clock,
  MapPin
} from 'lucide-react';
import { IdentityUser } from '../types/soc';
import { socApi } from '../services/api';

interface IdentityPageProps {
  onRefreshData?: () => void;
}

export const IdentityPage: React.FC<IdentityPageProps> = ({ onRefreshData }) => {
  const [identities, setIdentities] = useState<IdentityUser[]>([]);
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState<'All' | 'HighRisk' | 'Locked'>('All');
  const [selectedUser, setSelectedUser] = useState<IdentityUser | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);

  const loadIdentities = async () => {
    const data = await socApi.getIdentities();
    setIdentities(data);
    if (!selectedUser && data.length > 0) {
      setSelectedUser(data[0]);
    } else if (selectedUser) {
      const updated = data.find(u => u.id === selectedUser.id);
      if (updated) setSelectedUser(updated);
    }
  };

  useEffect(() => {
    loadIdentities();
  }, []);

  const handleStatusChange = async (user: IdentityUser, newStatus: IdentityUser['status']) => {
    setLoadingId(`status-${user.id}`);
    await socApi.updateIdentityStatus(user.id, newStatus);
    await loadIdentities();
    setLoadingId(null);
    setActionNotice(`Account ${user.username} state changed to "${newStatus}". Kerberos tickets flushed.`);
    setTimeout(() => setActionNotice(null), 5000);
    onRefreshData?.();
  };

  const handleRevokeSessions = async (user: IdentityUser) => {
    setLoadingId(`revoke-${user.id}`);
    await socApi.revokeIdentitySessions(user.id);
    await loadIdentities();
    setLoadingId(null);
    setActionNotice(`Flushed active OAuth refresh tokens and Kerberos tickets for ${user.username}.`);
    setTimeout(() => setActionNotice(null), 5000);
    onRefreshData?.();
  };

  const handleToggleMfa = async (user: IdentityUser) => {
    setLoadingId(`mfa-${user.id}`);
    const res = await socApi.toggleMfa(user.id);
    await loadIdentities();
    setLoadingId(null);
    setActionNotice(`MFA requirement set to ${res ? 'ENFORCED' : 'DISABLED'} for ${user.username}.`);
    setTimeout(() => setActionNotice(null), 5000);
    onRefreshData?.();
  };

  const filtered = identities.filter(u => {
    const matchesSearch =
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      u.displayName.toLowerCase().includes(search.toLowerCase()) ||
      u.department.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase());
    const matchesStatus =
      filterStatus === 'All'
        ? true
        : filterStatus === 'HighRisk'
        ? u.riskScore >= 70
        : u.status === 'Locked';
    return matchesSearch && matchesStatus;
  });

  const highRiskCount = identities.filter(u => u.riskScore >= 70).length;
  const lockedCount = identities.filter(u => u.status === 'Locked').length;
  const totalFailed = identities.reduce((acc, u) => acc + u.failedLogins24h, 0);

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Identity & Access Management (IAM) Threat Telemetry
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {identities.length} Monitored Principals
            </span>
            {highRiskCount > 0 && (
              <span className="text-[10px] bg-red-950/80 text-red-300 border border-red-500/40 px-2 py-0.5 rounded font-bold">
                {highRiskCount} High Risk Identities
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Active Directory & Entra ID credential telemetry, Kerberos pre-auth anomaly detection, and session revocation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative min-w-[200px]">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search User, Role, Email..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:border-cyan-400 outline-none text-xs"
            />
          </div>
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value as any)}
            className="bg-[#080d19] border border-[#1d2d4a] text-slate-300 rounded px-2.5 py-1.5 text-xs outline-none"
          >
            <option value="All">All Principals</option>
            <option value="HighRisk">High Risk (Score ≥ 70)</option>
            <option value="Locked">Locked Accounts</option>
          </select>
        </div>
      </div>

      {actionNotice && (
        <div className="bg-cyan-950/80 border border-cyan-500/40 p-2.5 rounded flex items-center gap-2 text-cyan-200 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-[#0b1324] border border-[#162238] p-3 rounded">
          <div className="text-[10px] text-slate-400">Total Monitored Accounts</div>
          <div className="text-lg font-bold text-slate-100 mt-1">{identities.length}</div>
        </div>
        <div className="bg-[#0b1324] border border-[#162238] p-3 rounded">
          <div className="text-[10px] text-slate-400">High Risk Identities</div>
          <div className="text-lg font-bold text-red-400 mt-1">{highRiskCount}</div>
        </div>
        <div className="bg-[#0b1324] border border-[#162238] p-3 rounded">
          <div className="text-[10px] text-slate-400">Failed Logins (24h)</div>
          <div className="text-lg font-bold text-amber-400 mt-1">{totalFailed}</div>
        </div>
        <div className="bg-[#0b1324] border border-[#162238] p-3 rounded">
          <div className="text-[10px] text-slate-400">Currently Locked</div>
          <div className="text-lg font-bold text-cyan-300 mt-1">{lockedCount}</div>
        </div>
      </div>

      {/* Main Grid: Directory Table & Identity Investigation Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Table */}
        <div className="lg:col-span-7 soc-card overflow-hidden">
          <div className="p-3 border-b border-[#18263f] flex items-center justify-between bg-[#080d18]">
            <span className="font-bold text-slate-200 text-xs">Directory Users & Service Principals</span>
            <span className="text-[10px] text-slate-400">Click to inspect authentication trail</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#080d18] text-[10px] text-slate-400 uppercase border-b border-[#18263f]">
                  <th className="py-2.5 px-3">Principal</th>
                  <th className="py-2.5 px-3">Department / Role</th>
                  <th className="py-2.5 px-3 text-center">MFA</th>
                  <th className="py-2.5 px-3 text-center">Status</th>
                  <th className="py-2.5 px-3 text-center">Failed Logins</th>
                  <th className="py-2.5 px-3 text-right">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#131d30]">
                {filtered.map(user => {
                  const isSelected = selectedUser?.id === user.id;
                  return (
                    <tr
                      key={user.id}
                      onClick={() => setSelectedUser(user)}
                      className={`hover:bg-[#111c30] cursor-pointer transition-colors ${
                        isSelected ? 'bg-cyan-950/30 border-l-2 border-cyan-400' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3">
                        <div className="font-bold text-slate-100 flex items-center gap-1.5">
                          <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{user.username}</span>
                        </div>
                        <div className="text-[10px] text-slate-400">{user.displayName}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="text-slate-200">{user.department}</div>
                        <div className="text-[10px] text-slate-500">{user.role}</div>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.2 rounded ${
                            user.mfaEnabled
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                              : 'bg-amber-950 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {user.mfaEnabled ? 'Enforced' : 'Disabled'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded inline-flex items-center gap-1 ${
                            user.status === 'Locked'
                              ? 'bg-red-950 text-red-300 border border-red-500/40'
                              : user.status === 'Suspended'
                              ? 'bg-amber-950 text-amber-300 border border-amber-500/30'
                              : 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                          }`}
                        >
                          {user.status === 'Locked' ? <Lock className="w-2.5 h-2.5" /> : null}
                          {user.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span
                          className={`font-bold text-xs ${
                            user.failedLogins24h > 10 ? 'text-red-400' : user.failedLogins24h > 0 ? 'text-amber-400' : 'text-slate-500'
                          }`}
                        >
                          {user.failedLogins24h}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <span
                          className={`font-bold px-2 py-0.5 rounded text-xs ${
                            user.riskScore >= 80
                              ? 'bg-red-950 text-red-400 border border-red-500/40'
                              : user.riskScore >= 60
                              ? 'bg-amber-950 text-amber-300 border border-amber-500/30'
                              : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {user.riskScore}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected User Detail & Remediation Actions */}
        <div className="lg:col-span-5 soc-card p-4 space-y-3 flex flex-col justify-between">
          {selectedUser ? (
            <>
              <div>
                <div className="flex items-center justify-between pb-2 border-b border-[#18263f]">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-slate-100">{selectedUser.displayName}</span>
                      <span className="text-[10px] text-cyan-400 font-mono">({selectedUser.username})</span>
                    </div>
                    <div className="text-[11px] text-slate-400">{selectedUser.email}</div>
                  </div>
                  <div
                    className={`text-xs font-bold px-2 py-1 rounded border ${
                      selectedUser.riskScore >= 80
                        ? 'bg-red-950 text-red-300 border-red-500/40'
                        : 'bg-cyan-950 text-cyan-300 border-cyan-500/40'
                    }`}
                  >
                    Risk: {selectedUser.riskScore}/100
                  </div>
                </div>

                {/* Telemetry Summary */}
                <div className="space-y-2 my-3 text-[11px]">
                  <div className="flex items-center justify-between bg-[#080d19] p-2 rounded border border-[#162238]">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      Last Successful Authentication:
                    </span>
                    <span className="text-slate-200 font-semibold">{selectedUser.lastLogin}</span>
                  </div>
                  <div className="flex items-center justify-between bg-[#080d19] p-2 rounded border border-[#162238]">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <MapPin className="w-3.5 h-3.5 text-cyan-400" />
                      Ingress Network Location:
                    </span>
                    <span className="text-slate-200 font-semibold">{selectedUser.lastLocation}</span>
                  </div>
                </div>

                {/* Anomalous Events */}
                <div className="space-y-1.5">
                  <div className="text-xs font-bold text-slate-200 flex items-center gap-1.5 mb-1">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                    <span>Correlated Identity Anomalies ({selectedUser.anomalousEvents.length})</span>
                  </div>
                  {selectedUser.anomalousEvents.length > 0 ? (
                    selectedUser.anomalousEvents.map((evt, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-red-950/20 border border-red-500/30 text-red-200 text-[11px] leading-relaxed flex items-start gap-2"
                      >
                        <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0 mt-0.5" />
                        <span>{evt}</span>
                      </div>
                    ))
                  ) : (
                    <div className="p-2 rounded bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 text-[11px] flex items-center gap-2">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Zero anomalous authentication anomalies detected for this account.</span>
                    </div>
                  )}
                </div>

                {/* Quick Action Buttons */}
                <div className="mt-4 pt-3 border-t border-[#18263f] space-y-2">
                  <span className="text-[10px] uppercase text-slate-400 font-bold tracking-wider">
                    Administrative Containment Controls
                  </span>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() => handleRevokeSessions(selectedUser)}
                      disabled={loadingId !== null}
                      className="p-2 rounded bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-200 text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{loadingId === `revoke-${selectedUser.id}` ? 'Revoking...' : 'Revoke Tokens'}</span>
                    </button>

                    <button
                      onClick={() => handleToggleMfa(selectedUser)}
                      disabled={loadingId !== null}
                      className="p-2 rounded bg-blue-950/60 hover:bg-blue-900 border border-blue-500/40 text-blue-200 text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <KeyRound className="w-3.5 h-3.5 text-blue-400" />
                      <span>{selectedUser.mfaEnabled ? 'Disable MFA' : 'Force MFA'}</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-2 gap-2 pt-1">
                    {selectedUser.status === 'Locked' ? (
                      <button
                        onClick={() => handleStatusChange(selectedUser, 'Active')}
                        disabled={loadingId !== null}
                        className="w-full p-2 rounded bg-emerald-950/70 hover:bg-emerald-900 border border-emerald-500/40 text-emerald-300 text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer"
                      >
                        <Unlock className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Unlock Account</span>
                      </button>
                    ) : (
                      <button
                        onClick={() => handleStatusChange(selectedUser, 'Locked')}
                        disabled={loadingId !== null}
                        className="w-full p-2 rounded bg-red-950/70 hover:bg-red-900 border border-red-500/40 text-red-300 text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer"
                      >
                        <Lock className="w-3.5 h-3.5 text-red-400" />
                        <span>Lock Account</span>
                      </button>
                    )}

                    <button
                      onClick={() => handleStatusChange(selectedUser, selectedUser.status === 'Suspended' ? 'Active' : 'Suspended')}
                      disabled={loadingId !== null}
                      className="w-full p-2 rounded bg-[#162238] hover:bg-[#1f3050] border border-[#2a3c5e] text-slate-300 text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <UserX className="w-3.5 h-3.5" />
                      <span>{selectedUser.status === 'Suspended' ? 'Unsuspend' : 'Suspend'}</span>
                    </button>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-[#18263f] text-[10px] text-slate-500 flex items-center justify-between">
                <span>Principal ID: {selectedUser.id}</span>
                <span className="text-cyan-400">Kerberos KDC Filter: Active</span>
              </div>
            </>
          ) : (
            <div className="py-12 text-center text-slate-500">
              Select an account to view identity details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
