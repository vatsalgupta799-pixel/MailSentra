import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { EmailParseResponse, ParsedEmail, ScanIncident, ScanDetail } from '../types';
import { LinkGuidanceCard } from '../components/LinkGuidanceCard';
import {
  Upload,
  FileCheck,
  AlertTriangle,
  Link2,
  Paperclip,
  Clock,
  Terminal,
  History,
  Search,
  Filter,
  CheckCircle2,
  ShieldAlert,
  ArrowLeft,
  RefreshCw,
} from 'lucide-react';

interface ScansProps {
  initialScanId?: number | null;
  onClearInitialScan?: () => void;
}

export const Scans: React.FC<ScansProps> = ({ initialScanId, onClearInitialScan }) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<EmailParseResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'urls' | 'attachments' | 'body'>('overview');
  const [isDragging, setIsDragging] = useState(false);

  // Persistent History State
  const [historyScans, setHistoryScans] = useState<ScanIncident[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [tierFilter, setTierFilter] = useState<string>('ALL');
  const [selectedHistoricalScan, setSelectedHistoricalScan] = useState<ScanDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Fetch scan history from backend
  const fetchHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await api.get<ScanIncident[]>('/scans?limit=50');
      setHistoryScans(res.data || []);
    } catch (err: any) {
      console.error('Failed to load scan history:', err);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  // If navigated from Dashboard with a specific scan ID
  useEffect(() => {
    if (initialScanId) {
      loadScanDetail(initialScanId);
      if (onClearInitialScan) onClearInitialScan();
    }
  }, [initialScanId]);

  const loadScanDetail = async (scanId: number | string) => {
    setDetailLoading(true);
    setError(null);
    try {
      const res = await api.get<ScanDetail>(`/scans/${scanId}`);
      setSelectedHistoricalScan(res.data);
      // Construct a compatible EmailParseResponse so existing analytical views render automatically
      const tel = res.data.telemetry || {};
      const urlAnalysisFindings = (tel.url_analysis && tel.url_analysis.findings) || [];
      const findingsByUrl = new Map<string, any>();
      urlAnalysisFindings.forEach((f: any) => {
        if (f.url) findingsByUrl.set(f.url, f);
      });

      const rawUrls = tel.urls || [];
      const enrichedUrls = rawUrls.map((u: any) => {
        const match = findingsByUrl.get(u.original_url) || findingsByUrl.get(u.normalized_url);
        if (match) {
          return {
            ...u,
            finding: u.finding || match,
            consequences: u.consequences || match.consequences,
            post_click_guidance: u.post_click_guidance || match.post_click_guidance,
          };
        }
        return u;
      });

      const reconstructedParsedEmail: ParsedEmail = {
        message_id: tel.message_id || res.data.subject,
        subject: res.data.subject,
        date_raw: tel.date_raw || null,
        date_utc: tel.date_utc || null,
        processing_timestamp: res.data.created_at,
        from_sender: tel.from_sender || (res.data.sender ? { raw: res.data.sender, address: res.data.sender, domain: res.data.sender.split('@')[1] || '', display_name: null } : null),
        reply_to: tel.reply_to || null,
        return_path: tel.return_path || null,
        to_recipients: tel.to_recipients || (res.data.recipient ? [{ raw: res.data.recipient, address: res.data.recipient, domain: res.data.recipient.split('@')[1] || '', display_name: null }] : []),
        cc_recipients: tel.cc_recipients || [],
        bcc_recipients: tel.bcc_recipients || [],
        received_hops: tel.received_hops || [],
        body_plain: tel.body_plain || null,
        body_html: tel.body_html || null,
        body_extracted_text: tel.body_extracted_text || null,
        urls: enrichedUrls,
        attachments: tel.attachments || [],
        parsing_warnings: tel.parsing_warnings || [],
      };

      setScanResult({
        scan_id: res.data.id,
        scan_uuid: res.data.scan_uuid,
        status: res.data.status,
        parsed_email: reconstructedParsedEmail,
        created_at: res.data.created_at,
      });
      // Scroll to result view
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err: any) {
      setError(err?.response?.data?.detail || `Failed to fetch telemetry for Scan #${scanId}`);
    } finally {
      setDetailLoading(false);
    }
  };

  const validateAndSetFile = (selectedFile: File) => {
    const maxSizeBytes = 15 * 1024 * 1024;
    if (selectedFile.size > maxSizeBytes) {
      setError(`Selected file (${(selectedFile.size / (1024 * 1024)).toFixed(1)}MB) exceeds maximum allowable limit of 15MB.`);
      setFile(null);
      return;
    }
    const ext = selectedFile.name.toLowerCase().split('.').pop();
    if (!['eml', 'msg', 'txt', 'mime'].includes(ext || '')) {
      setError(`File extension '.${ext}' is not supported. Please select an .eml, .msg, .txt, or .mime file.`);
      setFile(null);
      return;
    }
    setFile(selectedFile);
    setError(null);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select an .eml file to upload.');
      return;
    }

    setLoading(true);
    setError(null);
    setSelectedHistoricalScan(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await api.post<EmailParseResponse>('/scans/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      setScanResult(response.data);
      // Fetch scan details to get the final RiskEngine verdict and telemetry
      try {
        const detailRes = await api.get<ScanDetail>(`/scans/${response.data.scan_id}`);
        setSelectedHistoricalScan(detailRes.data);
      } catch (err) {
        // Fallback
      }
      // Refresh history table
      fetchHistory();
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Failed to upload and parse email. Ensure the backend is running.');
      }
    } finally {
      setLoading(false);
    }
  };

  const email: ParsedEmail | undefined = scanResult?.parsed_email;

  // Filter history
  const filteredHistory = historyScans.filter((s) => {
    const matchesSearch =
      (s.subject || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (s.sender || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.id.toString().includes(searchQuery);
    const matchesTier = tierFilter === 'ALL' || s.risk_tier === tierFilter;
    return matchesSearch && matchesTier;
  });

  return (
    <div className="space-y-8 font-sans">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Email Forensics & Ingestion Console</h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Ingest and inspect raw RFC 5322 (.eml) emails, deconstruct MIME trees, and review persistent scan incidents
          </p>
        </div>

        {scanResult && (
          <button
            onClick={() => {
              setScanResult(null);
              setSelectedHistoricalScan(null);
              setFile(null);
            }}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-semibold rounded-lg border border-gray-700 transition-colors w-fit"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>New File Ingestion</span>
          </button>
        )}
      </div>

      {/* Upload Dropzone (Collapsed if viewing result, or visible) */}
      {!scanResult && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <form onSubmit={handleUpload} className="space-y-4">
            <div className="flex flex-col md:flex-row items-center space-y-3 md:space-y-0 md:space-x-4">
              <label
                htmlFor="email-file-input"
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                className={`flex-1 w-full flex items-center justify-center px-6 py-4 border-2 border-dashed rounded-lg cursor-pointer transition-colors ${
                  isDragging
                    ? 'border-blue-400 bg-blue-950/30'
                    : 'border-gray-700 hover:border-blue-500/60 bg-gray-950/50 hover:bg-gray-950'
                }`}
              >
                <div className="flex items-center space-x-3 text-center">
                  <Upload className="w-5 h-5 text-gray-400" />
                  <span className="text-xs text-gray-300">
                    {file ? file.name : 'Select or drag-and-drop a raw .eml file (Max 15MB)'}
                  </span>
                </div>
                <input
                  id="email-file-input"
                  name="email-file"
                  type="file"
                  className="hidden"
                  onChange={handleFileChange}
                  accept=".eml,.msg,.txt,.mime"
                />
              </label>

              <button
                type="submit"
                disabled={loading || !file}
                className={`w-full md:w-auto px-6 py-4 rounded-lg font-medium text-xs flex items-center justify-center space-x-2 transition-colors ${
                  loading || !file
                    ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/30'
                }`}
              >
                {loading ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analyzing Payload...</span>
                  </>
                ) : (
                  <>
                    <FileCheck className="w-4 h-4" />
                    <span>Parse &amp; Normalize</span>
                  </>
                )}
              </button>
            </div>

            {error && (
              <div className="p-3 bg-red-950/40 border border-red-800/80 rounded-lg text-xs text-red-300 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </form>
        </div>
      )}

      {/* Active Scan Telemetry Results View */}
      {scanResult && email && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <div className="p-5 bg-gray-900 border border-gray-800 rounded-xl space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-gray-800">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-xs text-blue-400 font-bold">
                    Scan Incident #{scanResult.scan_id}
                  </span>
                  <span className="text-gray-600">•</span>
                  <span className="text-[11px] font-mono text-gray-400 truncate max-w-xs">
                    UUID: {scanResult.scan_uuid}
                  </span>
                </div>
                <div className="text-[11px] text-gray-500 flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5" />
                  <span>Processed: {new Date(scanResult.created_at).toLocaleString()}</span>
                </div>
              </div>

              {selectedHistoricalScan && (
                <div className="flex items-center space-x-3">
                  <div className="text-right">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wide block">Risk Score</span>
                    <span
                      className={`text-2xl font-bold font-mono ${
                        selectedHistoricalScan.risk_tier === 'MALICIOUS'
                          ? 'text-rose-400'
                          : selectedHistoricalScan.risk_tier === 'SUSPICIOUS'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {selectedHistoricalScan.risk_score.toFixed(1)}
                    </span>
                  </div>
                  <div
                    className={`px-3 py-1.5 rounded-lg border font-bold text-xs uppercase flex items-center space-x-1.5 ${
                      selectedHistoricalScan.risk_tier === 'MALICIOUS'
                        ? 'bg-rose-950/60 text-rose-300 border-rose-800'
                        : selectedHistoricalScan.risk_tier === 'SUSPICIOUS'
                        ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                        : 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                    }`}
                  >
                    {selectedHistoricalScan.risk_tier === 'MALICIOUS' ? (
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                    ) : selectedHistoricalScan.risk_tier === 'SUSPICIOUS' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    )}
                    <span>{selectedHistoricalScan.risk_tier}</span>
                  </div>
                </div>
              )}
            </div>

            {selectedHistoricalScan?.verdict_summary && (
              <div className="text-xs text-gray-300 bg-gray-950/60 p-3 rounded-lg border border-gray-800">
                <span className="font-semibold text-white">Forensic Verdict Summary: </span>
                <span>{selectedHistoricalScan.verdict_summary}</span>
              </div>
            )}

            {/* Email Metadata Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans">
              <div>
                <span className="text-gray-500 block">Subject:</span>
                <span className="text-sm font-semibold text-white">{email.subject || '<No Subject>'}</span>
              </div>
              <div>
                <span className="text-gray-500 block">From (Sender):</span>
                <span className="text-sm text-gray-200">
                  {email.from_sender ? (
                    <>
                      <span className="font-semibold text-white">{email.from_sender.display_name || ''} </span>
                      <span className="font-mono text-blue-400">&lt;{email.from_sender.address}&gt;</span>
                    </>
                  ) : (
                    '<Missing From Header>'
                  )}
                </span>
              </div>
              <div>
                <span className="text-gray-500 block">To (Recipients):</span>
                <span className="text-gray-300 font-mono">
                  {email.to_recipients.map((r) => r.address).join(', ') || '<None>'}
                </span>
              </div>
              <div>
                <span className="text-gray-500 block">Message-ID:</span>
                <span className="text-gray-300 font-mono truncate block">
                  {email.message_id || '<Missing Message-ID>'}
                </span>
              </div>
            </div>

            {/* Parsing Warnings */}
            {email.parsing_warnings.length > 0 && (
              <div className="mt-4 p-3 bg-amber-950/30 border border-amber-800/40 rounded-lg text-xs space-y-1">
                <div className="flex items-center space-x-1.5 text-amber-400 font-semibold">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Parsing Diagnostic Warnings ({email.parsing_warnings.length})</span>
                </div>
                <ul className="list-disc list-inside text-amber-200/80 font-mono text-[11px] space-y-0.5">
                  {email.parsing_warnings.map((w, idx) => (
                    <li key={idx}>{w}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Navigation Tabs */}
          <div className="flex border-b border-gray-800 space-x-4">
            <button
              onClick={() => setActiveTab('overview')}
              className={`pb-2 text-xs font-medium border-b-2 transition-colors ${
                activeTab === 'overview'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              Overview &amp; Hops ({email.received_hops.length})
            </button>
            <button
              onClick={() => setActiveTab('urls')}
              className={`pb-2 text-xs font-medium border-b-2 transition-colors flex items-center space-x-1 ${
                activeTab === 'urls'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>Extracted URLs &amp; Consequences ({email.urls.length})</span>
            </button>
            <button
              onClick={() => setActiveTab('attachments')}
              className={`pb-2 text-xs font-medium border-b-2 transition-colors flex items-center space-x-1 ${
                activeTab === 'attachments'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              <Paperclip className="w-3.5 h-3.5" />
              <span>Attachments ({email.attachments.length})</span>
            </button>
            <button
              onClick={() => setActiveTab('body')}
              className={`pb-2 text-xs font-medium border-b-2 transition-colors flex items-center space-x-1 ${
                activeTab === 'body'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Safe Body Text</span>
            </button>
          </div>

          {/* Tab Content */}
          {activeTab === 'overview' && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                Received Hop Trace ({email.received_hops.length} Hops)
              </h4>
              {email.received_hops.length === 0 ? (
                <p className="text-xs text-gray-500 italic">No Received hops present in headers.</p>
              ) : (
                <div className="space-y-3">
                  {email.received_hops.map((hop) => (
                    <div key={hop.hop_number} className="p-3 bg-gray-950 rounded-lg border border-gray-800 text-xs font-mono space-y-1">
                      <div className="flex items-center justify-between text-blue-400">
                        <span className="font-bold">Hop #{hop.hop_number}</span>
                        <span className="text-gray-500 text-[11px]">{hop.date || ''}</span>
                      </div>
                      <div className="text-gray-300 truncate">By: {hop.by || '<unknown>'}</div>
                      <div className="text-gray-400 truncate">From: {hop.from_host || '<unknown>'} (IP: {hop.ip || 'none'})</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'urls' && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="px-6 py-3 border-b border-gray-800 bg-gray-950 text-xs font-semibold text-gray-400">
                Extracted Hyperlinks (Defanged) &amp; Educational Consequence Analysis
              </div>
              {email.urls.length === 0 ? (
                <div className="p-8 text-center text-xs text-gray-500">No URLs detected in plain text or HTML body.</div>
              ) : (
                <div className="divide-y divide-gray-800">
                  {email.urls.map((u, i) => (
                    <div key={i} className="p-4 hover:bg-gray-850/50 transition-colors space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs text-emerald-400 font-semibold break-all">
                          {u.defanged_url}
                        </span>
                        <div className="flex items-center space-x-2">
                          {u.is_duplicate && (
                            <span className="px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] rounded">
                              Duplicate ({u.occurrence_count}x)
                            </span>
                          )}
                          <span className="px-1.5 py-0.5 bg-gray-800 text-gray-400 font-mono text-[10px] rounded">
                            {u.source_location}
                          </span>
                        </div>
                      </div>
                      {u.visible_text && (
                        <div className="text-[11px] text-gray-400">
                          Anchor Text: <span className="text-gray-200">"{u.visible_text}"</span>
                        </div>
                      )}

                      {/* Educational Consequence Card & Post-Click Assistance */}
                      <LinkGuidanceCard urlItem={u} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'attachments' && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="px-6 py-3 border-b border-gray-800 bg-gray-950 text-xs font-semibold text-gray-400">
                Attachment Forensics &amp; Cryptographic Hashes
              </div>
              {email.attachments.length === 0 ? (
                <div className="p-8 text-center text-xs text-gray-500">No attachments found in this message.</div>
              ) : (
                <div className="divide-y divide-gray-800">
                  {email.attachments.map((att, i) => (
                    <div key={i} className="p-4 hover:bg-gray-850/50 transition-colors space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Paperclip className="w-4 h-4 text-blue-400" />
                          <span className="font-semibold text-sm text-white font-mono">{att.filename}</span>
                          {att.is_double_extension && (
                            <span className="px-2 py-0.5 bg-red-500/10 text-red-400 border border-red-500/20 text-[10px] font-bold rounded">
                              SUSPICIOUS DOUBLE EXTENSION
                            </span>
                          )}
                        </div>
                        <span className="text-xs text-gray-400 font-mono">
                          {(att.size_bytes / 1024).toFixed(1)} KB
                        </span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono text-gray-400">
                        <div>MIME: <span className="text-gray-300">{att.content_type}</span></div>
                        <div>Disposition: <span className="text-gray-300">{att.content_disposition}</span></div>
                        <div className="md:col-span-2">
                          SHA-256: <span className="text-amber-400 break-all">{att.sha256_hash}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'body' && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                  Safe Plain Text Content (Scripts Decomposed)
                </span>
                <span className="text-[11px] text-gray-500 font-mono">Untrusted HTML Disabled</span>
              </div>
              <pre className="p-4 bg-gray-950 rounded-lg border border-gray-800 text-xs font-mono text-gray-300 whitespace-pre-wrap max-h-96 overflow-y-auto">
                {email.body_extracted_text || email.body_plain || '<No text body content>'}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Persistent Scan History Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden space-y-4 p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <History className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-bold text-white">Persistent Scan Incidents History</h2>
          </div>

          <button
            onClick={fetchHistory}
            disabled={historyLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs transition-colors border border-gray-700 w-fit"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${historyLoading ? 'animate-spin' : ''}`} />
            <span>Reload</span>
          </button>
        </div>

        {/* Search & Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-3 text-gray-500" />
            <input
              type="text"
              placeholder="Search by ID, subject, or sender..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          <div className="flex items-center space-x-2">
            <Filter className="w-4 h-4 text-gray-500" />
            <select
              value={tierFilter}
              onChange={(e) => setTierFilter(e.target.value)}
              className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
            >
              <option value="ALL">All Tiers</option>
              <option value="CLEAN">Clean Only</option>
              <option value="SUSPICIOUS">Suspicious Only</option>
              <option value="MALICIOUS">Malicious Only</option>
            </select>
          </div>
        </div>

        {/* History Table */}
        <div className="overflow-x-auto">
          {filteredHistory.length === 0 ? (
            <div className="p-8 text-center text-xs text-gray-500">
              {historyLoading ? 'Loading incident records...' : 'No scan incidents match your search criteria.'}
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 border-b border-gray-800 font-mono text-[11px]">
                <tr>
                  <th className="p-3">ID</th>
                  <th className="p-3">Date</th>
                  <th className="p-3">Subject</th>
                  <th className="p-3">Sender</th>
                  <th className="p-3">Verdict</th>
                  <th className="p-3">Score</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 font-sans">
                {filteredHistory.map((h) => {
                  const isMal = h.risk_tier === 'MALICIOUS';
                  const isSusp = h.risk_tier === 'SUSPICIOUS';
                  return (
                    <tr key={h.id} className="hover:bg-gray-850/50 transition-colors">
                      <td className="p-3 font-mono text-gray-400">#{h.id}</td>
                      <td className="p-3 text-gray-400 font-mono text-[11px]">
                        {new Date(h.created_at).toLocaleDateString()}
                      </td>
                      <td className="p-3 font-medium text-white max-w-[220px] truncate">
                        {h.subject || '<No Subject>'}
                      </td>
                      <td className="p-3 text-gray-300 font-mono text-[11px] max-w-[160px] truncate">
                        {h.sender || '<Unknown>'}
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
                          {h.risk_tier}
                        </span>
                      </td>
                      <td className="p-3 font-mono font-bold">
                        <span className={isMal ? 'text-rose-400' : isSusp ? 'text-amber-400' : 'text-emerald-400'}>
                          {h.risk_score.toFixed(1)}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={() => loadScanDetail(h.id)}
                          disabled={detailLoading}
                          className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold transition-colors"
                        >
                          Load Details
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
    </div>
  );
};
