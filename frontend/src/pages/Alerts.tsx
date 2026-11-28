import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { SecurityAlert, AlertStatus } from '../types';
import {
  ShieldAlert,
  Filter,
  Search,
  RefreshCw,
  Clock,
  ChevronRight,
} from 'lucide-react';

interface AlertsProps {
  onSelectScan?: (scanId: number) => void;
  onNavigateTab?: (tab: string) => void;
}

export const Alerts: React.FC<AlertsProps> = ({ onSelectScan, onNavigateTab }) => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [updatingId, setUpdatingId] = useState<number | null>(null);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const url = statusFilter === 'ALL' ? '/alerts?limit=50' : `/alerts?status=${statusFilter}&limit=50`;
      const res = await api.get<SecurityAlert[]>(url);
      setAlerts(res.data || []);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to load security alerts from backend API.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [statusFilter]);

  const handleUpdateStatus = async (alertId: number, newStatus: AlertStatus) => {
    setUpdatingId(alertId);
    try {
      const res = await api.patch<SecurityAlert>(`/alerts/${alertId}/status`, { status: newStatus });
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? res.data : a)));
    } catch (err: any) {
      alert(`Failed to update alert status: ${err?.response?.data?.detail || err.message}`);
    } finally {
      setUpdatingId(null);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    const q = searchQuery.toLowerCase();
    const titleMatch = (a.title || '').toLowerCase().includes(q);
    const descMatch = (a.description || '').toLowerCase().includes(q);
    const idMatch = a.id.toString().includes(q) || (a.scan_id ? a.scan_id.toString().includes(q) : false);
    return titleMatch || descMatch || idMatch;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Security Alerts &amp; Incident Triage</h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Real-time high-risk threat notifications generated from malicious and high-score email detections
          </p>
        </div>

        <button
          onClick={fetchAlerts}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs transition-colors border border-gray-700 w-fit"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Reload Alerts</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-red-950/40 border border-red-800/80 rounded-xl text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 bg-gray-900 border border-gray-800 p-4 rounded-xl">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-3 text-gray-500" />
          <input
            type="text"
            placeholder="Search alerts by title, description, or scan ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-gray-950 border border-gray-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
        </div>

        <div className="flex items-center space-x-2">
          <Filter className="w-4 h-4 text-gray-500" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open Only</option>
            <option value="IN_TRIAGE">In Triage</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      <div className="space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center text-xs text-gray-500">
            {loading ? 'Loading alert incidents from backend...' : 'No security alerts currently match your filters.'}
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isCrit = alert.severity === 'CRITICAL';
            const isHigh = alert.severity === 'HIGH';

            return (
              <div
                key={alert.id}
                className="bg-gray-900 border border-gray-800 hover:border-gray-700 rounded-xl p-5 transition-all space-y-3"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="flex items-start space-x-3">
                    <div
                      className={`p-2 rounded-lg border mt-0.5 ${
                        isCrit
                          ? 'bg-red-500/10 text-red-400 border-red-500/20'
                          : isHigh
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                          : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                      }`}
                    >
                      <ShieldAlert className="w-5 h-5" />
                    </div>

                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold text-sm text-white">{alert.title}</span>
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                            isCrit
                              ? 'bg-red-500/20 text-red-300 border-red-500/30'
                              : isHigh
                              ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                              : 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                          }`}
                        >
                          {alert.severity}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700 uppercase">
                          Status: {alert.status}
                        </span>
                      </div>
                      <div className="text-xs text-gray-400 flex items-center space-x-2">
                        <Clock className="w-3.5 h-3.5 text-gray-500" />
                        <span>Created: {new Date(alert.created_at).toLocaleString()}</span>
                        {alert.scan_id && (
                          <>
                            <span className="text-gray-600">•</span>
                            <span className="font-mono text-blue-400">Scan ID: #{alert.scan_id}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Triage Actions */}
                  <div className="flex flex-wrap items-center gap-2">
                    {alert.scan_id && onSelectScan && onNavigateTab && (
                      <button
                        onClick={() => {
                          onSelectScan(alert.scan_id!);
                          onNavigateTab('scans');
                        }}
                        className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-blue-400 hover:text-blue-300 rounded text-xs font-semibold transition-colors border border-gray-700 flex items-center space-x-1"
                      >
                        <span>View Scan</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    )}

                    <select
                      value={alert.status}
                      disabled={updatingId === alert.id}
                      onChange={(e) => handleUpdateStatus(alert.id, e.target.value as AlertStatus)}
                      className="bg-gray-950 border border-gray-800 rounded px-2.5 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
                    >
                      <option value="OPEN">Mark Open</option>
                      <option value="IN_TRIAGE">Mark In Triage</option>
                      <option value="RESOLVED">Mark Resolved</option>
                      <option value="FALSE_POSITIVE">Mark False Positive</option>
                    </select>
                  </div>
                </div>

                <div className="text-xs text-gray-300 bg-gray-950/50 p-3 rounded-lg border border-gray-800/80 leading-relaxed">
                  {alert.description}
                </div>

                {/* Contributing Indicators */}
                {alert.indicators && Object.keys(alert.indicators).length > 0 && (
                  <div className="text-[11px] text-gray-400 font-mono space-y-1 bg-gray-950/30 p-2.5 rounded border border-gray-800/60">
                    <span className="text-gray-300 font-semibold block">Incident Indicators:</span>
                    <div>
                      Risk Tier: <span className="text-rose-400">{String(alert.indicators.risk_tier || 'N/A')}</span> | Risk Score: <span className="text-rose-400">{String(alert.indicators.risk_score || 'N/A')}</span>
                    </div>
                    {Array.isArray(alert.indicators.signals) && alert.indicators.signals.length > 0 && (
                      <ul className="list-disc list-inside space-y-0.5 text-gray-400">
                        {alert.indicators.signals.map((sig: string, idx: number) => (
                          <li key={idx} className="truncate">{sig}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
