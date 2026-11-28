import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { DashboardStats, ScanIncident, HealthStatus } from '../types';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Mail,
  Activity,
  Flame,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ChevronRight,
} from 'lucide-react';

interface DashboardProps {
  onSelectScan?: (scanId: number) => void;
  onNavigateTab?: (tab: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onSelectScan, onNavigateTab }) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<ScanIncident[]>([]);
  const [highRiskScans, setHighRiskScans] = useState<ScanIncident[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchDashboardData = async (retryOnAuthError = true) => {
    setIsRefreshing(true);
    try {
      const healthPromise = api.get<HealthStatus>('/health').then((r) => setHealth(r.data)).catch(() => {});
      const [statsRes, scansRes] = await Promise.all([
        api.get<DashboardStats>('/scans/stats'),
        api.get<ScanIncident[]>('/scans?limit=15'),
      ]);
      await healthPromise;

      setStats(statsRes.data);
      const allScans = scansRes.data || [];
      setRecentScans(allScans);
      // High risk scans: risk score >= 70 or MALICIOUS
      const highRisk = allScans.filter((s) => s.risk_score >= 70 || s.risk_tier === 'MALICIOUS');
      setHighRiskScans(highRisk);
      setError(null);
    } catch (err: any) {
      const detail = String(err?.response?.data?.detail || '');
      if (retryOnAuthError && (detail.toLowerCase().includes('bearer') || detail.toLowerCase().includes('token') || err?.response?.status === 401)) {
        localStorage.removeItem('mailsentra_token');
        return fetchDashboardData(false);
      }
      setError(detail || 'Failed to load live SOC dashboard metrics. Verify backend service is running.');
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const timer = setInterval(fetchDashboardData, 20000); // 20s auto-refresh
    return () => clearInterval(timer);
  }, []);

  const total = stats?.total_scanned || 0;
  const cleanCount = stats?.clean_count || 0;
  const suspiciousCount = stats?.suspicious_count || 0;
  const maliciousCount = stats?.malicious_count || 0;

  // Percentage calculations
  const cleanPct = total > 0 ? ((cleanCount / total) * 100).toFixed(1) : '0.0';
  const suspiciousPct = total > 0 ? ((suspiciousCount / total) * 100).toFixed(1) : '0.0';
  const maliciousPct = total > 0 ? ((maliciousCount / total) * 100).toFixed(1) : '0.0';

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner / Control Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 bg-gradient-to-r from-gray-900 via-gray-900 to-gray-950 border border-gray-800 rounded-xl">
        <div>
          <div className="flex items-center space-x-2.5">
            <h1 className="text-xl font-bold text-white tracking-tight">Security Operations Dashboard</h1>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded">
              LIVE TELEMETRY
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Real-time inbound email threat monitoring, forensic arbitration, and automated threat tiering
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {/* Health Pill */}
          <div className="flex items-center space-x-2 px-3 py-1.5 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                health?.database_connected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <span className="text-gray-400">Database:</span>
            <span className={health?.database_connected ? 'text-emerald-400 font-semibold' : 'text-amber-400'}>
              {health?.database_connected ? 'ONLINE' : 'DEGRADED'}
            </span>
          </div>

          {/* Refresh Button */}
          <button
            onClick={() => fetchDashboardData()}
            disabled={isRefreshing}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded-lg transition-colors border border-gray-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-blue-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 bg-red-950/40 border border-red-800/80 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-red-300">
          <div className="flex items-center space-x-2">
            <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => {
              localStorage.removeItem('mailsentra_token');
              fetchDashboardData(false);
            }}
            className="underline text-red-200 hover:text-white flex-shrink-0"
          >
            Clear Stale Token & Reconnect
          </button>
        </div>
      )}

      {/* Overview Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3.5">
        {/* Total Scanned */}
        <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Total Ingested</span>
            <Mail className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{loading ? '...' : total}</div>
          <div className="text-[11px] text-gray-500">All RFC 5322 payloads</div>
        </div>

        {/* Clean */}
        <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Clean Baseline</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">{loading ? '...' : cleanCount}</div>
          <div className="text-[11px] text-emerald-500/80 font-mono">{cleanPct}% of traffic</div>
        </div>

        {/* Suspicious */}
        <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Suspicious Tier</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono">{loading ? '...' : suspiciousCount}</div>
          <div className="text-[11px] text-amber-500/80 font-mono">{suspiciousPct}% elevated risk</div>
        </div>

        {/* Malicious */}
        <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Malicious Tier</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">{loading ? '...' : maliciousCount}</div>
          <div className="text-[11px] text-rose-500/80 font-mono">{maliciousPct}% confirmed threat</div>
        </div>

        {/* High Risk Findings */}
        <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>High Risk (&ge;70)</span>
            <Flame className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-orange-400 font-mono">
            {loading ? '...' : stats?.high_risk_findings_count ?? 0}
          </div>
          <div className="text-[11px] text-orange-500/80">Immediate attention</div>
        </div>

        {/* Threat Detection Rate */}
        <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Detection Rate</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400 font-mono">
            {loading ? '...' : `${stats?.threat_detection_rate ?? 0}%`}
          </div>
          <div className="text-[11px] text-gray-500">(Suspicious + Malicious) / Total</div>
        </div>
      </div>

      {/* Threat Distribution Visual Bar */}
      <div className="p-5 bg-gray-900 border border-gray-800 rounded-xl space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-white uppercase tracking-wider">Inbound Threat Distribution</span>
          <span className="text-gray-400 font-mono text-[11px]">Database-wide aggregate ({total} records)</span>
        </div>

        {/* Multi-segment Progress Bar */}
        <div className="h-3 w-full bg-gray-950 rounded-full overflow-hidden flex border border-gray-800">
          <div
            style={{ width: `${cleanPct}%` }}
            className="bg-emerald-500 transition-all duration-500"
            title={`Clean: ${cleanCount} (${cleanPct}%)`}
          />
          <div
            style={{ width: `${suspiciousPct}%` }}
            className="bg-amber-500 transition-all duration-500"
            title={`Suspicious: ${suspiciousCount} (${suspiciousPct}%)`}
          />
          <div
            style={{ width: `${maliciousPct}%` }}
            className="bg-rose-600 transition-all duration-500"
            title={`Malicious: ${maliciousCount} (${maliciousPct}%)`}
          />
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-6 text-xs text-gray-400 pt-1">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span>Clean: <strong className="text-white font-mono">{cleanCount}</strong> ({cleanPct}%)</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
            <span>Suspicious: <strong className="text-white font-mono">{suspiciousCount}</strong> ({suspiciousPct}%)</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-600" />
            <span>Malicious: <strong className="text-white font-mono">{maliciousCount}</strong> ({maliciousPct}%)</span>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Recent Scans + High-Risk Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Recent Inbound Incidents Table (2 Cols) */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between bg-gray-950">
            <div className="flex items-center space-x-2">
              <Mail className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-bold text-white">Recent Email Scans</h2>
            </div>
            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab('scans')}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center space-x-1"
              >
                <span>View All Scans</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex-1 overflow-x-auto">
            {recentScans.length === 0 ? (
              <div className="p-12 text-center text-xs text-gray-500">
                No email scans recorded in the database yet. Use the Email Scans page to ingest an .eml file.
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-950/70 text-gray-400 border-b border-gray-800 font-mono text-[11px]">
                  <tr>
                    <th className="p-3">ID</th>
                    <th className="p-3">Subject</th>
                    <th className="p-3">Sender</th>
                    <th className="p-3">Verdict</th>
                    <th className="p-3">Score</th>
                    <th className="p-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60 font-sans">
                  {recentScans.slice(0, 8).map((scan) => {
                    const isMal = scan.risk_tier === 'MALICIOUS';
                    const isSusp = scan.risk_tier === 'SUSPICIOUS';
                    return (
                      <tr key={scan.id} className="hover:bg-gray-850/50 transition-colors">
                        <td className="p-3 font-mono text-gray-400">#{scan.id}</td>
                        <td className="p-3 font-medium text-white max-w-[200px] truncate">
                          {scan.subject || '<No Subject>'}
                        </td>
                        <td className="p-3 text-gray-300 font-mono text-[11px] max-w-[160px] truncate">
                          {scan.sender || '<Unknown>'}
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                              isMal
                                ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                                : isSusp
                                ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            }`}
                          >
                            {scan.risk_tier}
                          </span>
                        </td>
                        <td className="p-3 font-mono font-bold">
                          <span
                            className={
                              isMal ? 'text-rose-400' : isSusp ? 'text-amber-400' : 'text-emerald-400'
                            }
                          >
                            {scan.risk_score.toFixed(1)}
                          </span>
                        </td>
                        <td className="p-3 text-right">
                          <button
                            onClick={() => {
                              if (onSelectScan) onSelectScan(scan.id);
                              if (onNavigateTab) onNavigateTab('scans');
                            }}
                            className="px-2.5 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white rounded text-[11px] font-medium transition-colors"
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Right Column: High-Risk Threat Queue (1 Col) */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between bg-gray-950">
            <div className="flex items-center space-x-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <h2 className="text-sm font-bold text-white">High-Risk Priority Queue</h2>
            </div>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
              {highRiskScans.length} Critical
            </span>
          </div>

          <div className="p-4 space-y-3 flex-1 overflow-y-auto max-h-[380px]">
            {highRiskScans.length === 0 ? (
              <div className="p-8 text-center text-xs text-gray-500 flex flex-col items-center space-y-2">
                <CheckCircle2 className="w-6 h-6 text-emerald-500/60" />
                <span>No critical or malicious threats currently require triage.</span>
              </div>
            ) : (
              highRiskScans.map((hScan) => (
                <div
                  key={hScan.id}
                  onClick={() => {
                    if (onSelectScan) onSelectScan(hScan.id);
                    if (onNavigateTab) onNavigateTab('scans');
                  }}
                  className="p-3 bg-gray-950/70 border border-rose-900/40 hover:border-rose-500/50 rounded-lg cursor-pointer transition-all space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white truncate max-w-[180px]">
                      {hScan.subject || 'Untitled Incident'}
                    </span>
                    <span className="font-mono text-xs font-bold text-rose-400">
                      Score: {hScan.risk_score.toFixed(1)}
                    </span>
                  </div>
                  <div className="text-[11px] text-gray-400 truncate font-mono">
                    From: {hScan.sender || '<Unknown>'}
                  </div>
                  <div className="text-[10px] text-gray-500 line-clamp-2 leading-relaxed">
                    {hScan.verdict_summary || 'Multi-vector threat indicators triggered.'}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
