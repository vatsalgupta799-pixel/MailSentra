import React, { useEffect, useState } from 'react';
import axios from 'axios';
import api from '../services/api';
import { AuditRecord } from '../types';
import {
  Search,
  Filter,
  RefreshCw,
  Lock,
  Key,
} from 'lucide-react';

export const Audit: React.FC = () => {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const url = actionFilter === 'ALL' ? '/audit?limit=50' : `/audit?action=${actionFilter}&limit=50`;
      const res = await api.get<AuditRecord[]>(url);
      setRecords(res.data || []);
      setError(null);
    } catch (err: any) {
      if (err?.response?.status === 401 || err?.response?.status === 403) {
        setError('Access Denied: The security audit trail is restricted to authorized Auditors and Administrators under RBAC policy.');
      } else {
        setError(err?.response?.data?.detail || 'Failed to retrieve append-only security audit trail from backend.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDevAdminLogin = async () => {
    setIsAuthenticating(true);
    try {
      const params = new URLSearchParams();
      params.append('username', 'admin@mailsentra.local');
      params.append('password', 'MailSentraAdmin2026!');
      const res = await axios.post('/api/v1/auth/login', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      if (res.data?.access_token) {
        localStorage.setItem('mailsentra_token', res.data.access_token);
        await fetchAuditLogs();
      }
    } catch (err: any) {
      setError('Failed to authenticate with development administrator credentials.');
    } finally {
      setIsAuthenticating(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, [actionFilter]);

  const filteredRecords = records.filter((r) => {
    const q = searchQuery.toLowerCase();
    const actorMatch = (r.actor_id || '').toLowerCase().includes(q);
    const actionMatch = (r.action || '').toLowerCase().includes(q);
    const resourceMatch = (r.resource_type || '').toLowerCase().includes(q) || (r.resource_id || '').toLowerCase().includes(q);
    return actorMatch || actionMatch || resourceMatch;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Security Audit Trail (Append-Only)</h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Tamper-evident log of administrative events, ingestion operations, and security detections from table <code className="text-gray-300 font-mono">audit_records</code>
          </p>
        </div>

        <button
          onClick={fetchAuditLogs}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs transition-colors border border-gray-700 w-fit"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Reload Audit Log</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-amber-950/40 border border-amber-800/80 rounded-xl text-xs text-amber-300 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <Lock className="w-4 h-4 text-amber-400 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={handleDevAdminLogin}
            disabled={isAuthenticating}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-black font-semibold rounded text-xs transition-colors w-fit flex-shrink-0"
          >
            <Key className="w-3.5 h-3.5" />
            <span>{isAuthenticating ? 'Authenticating...' : 'Authenticate as Dev Admin'}</span>
          </button>
        </div>
      )}

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3 bg-gray-900 border border-gray-800 p-4 rounded-xl">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-3 text-gray-500" />
          <input
            type="text"
            placeholder="Search by actor, action, or resource ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-gray-950 border border-gray-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
        </div>

        <div className="flex items-center space-x-2">
          <Filter className="w-4 h-4 text-gray-500" />
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Actions</option>
            <option value="EMAIL_INGESTED_AND_PARSED">EMAIL_INGESTED_AND_PARSED</option>
            <option value="USER_LOGIN">USER_LOGIN</option>
            <option value="ALERT_STATUS_UPDATED">ALERT_STATUS_UPDATED</option>
          </select>
        </div>
      </div>

      {/* Audit Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          {filteredRecords.length === 0 ? (
            <div className="p-12 text-center text-xs text-gray-500">
              {loading ? 'Reading audit trail from database...' : 'No audit records match your query.'}
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 border-b border-gray-800 font-mono text-[11px]">
                <tr>
                  <th className="p-3">ID</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Actor</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Resource</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Safe Metadata</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 font-sans">
                {filteredRecords.map((r) => {
                  const isSuccess = r.status === 'SUCCESS';
                  return (
                    <tr key={r.id} className="hover:bg-gray-850/50 transition-colors">
                      <td className="p-3 font-mono text-gray-500">#{r.id}</td>
                      <td className="p-3 text-gray-400 font-mono text-[11px] whitespace-nowrap">
                        {new Date(r.created_at).toLocaleString()}
                      </td>
                      <td className="p-3 text-gray-300 font-mono text-[11px]">{r.actor_id}</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono text-[10px]">
                          {r.action}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-[11px] text-gray-400">
                        {r.resource_type}:{r.resource_id || 'none'}
                      </td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[10px] uppercase font-semibold ${
                            isSuccess
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-red-500/10 text-red-400 border border-red-500/20'
                          }`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-[11px] text-gray-400 max-w-xs truncate">
                        {r.details ? JSON.stringify(r.details) : '{}'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
