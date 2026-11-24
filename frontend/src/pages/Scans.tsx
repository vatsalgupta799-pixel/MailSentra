import React, { useState } from 'react';
import api from '../services/api';
import { EmailParseResponse, ParsedEmail } from '../types';
import {
  Upload,
  FileCheck,
  AlertTriangle,
  Link2,
  Paperclip,
  Clock,
  Terminal,
} from 'lucide-react';

export const Scans: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<EmailParseResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'urls' | 'attachments' | 'body'>('overview');
  const [isDragging, setIsDragging] = useState(false);

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

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await api.post<EmailParseResponse>('/scans/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      setScanResult(response.data);
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Email Ingestion & Parsing Console</h2>
          <p className="text-xs text-gray-400">
            Upload raw RFC 5322 (.eml) emails for parsing, header normalization, and observable extraction
          </p>
        </div>
      </div>

      {/* Upload Box */}
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
              <div className="flex items-center space-x-3 text-sm text-gray-400">
                <Upload className="w-5 h-5 text-blue-400" />
                <span>
                  {file ? (
                    <span className="text-blue-400 font-medium font-mono">{file.name}</span>
                  ) : (
                    'Select or drag-and-drop a raw .eml file (Max 15MB)'
                  )}
                </span>
              </div>
              <input
                id="email-file-input"
                aria-label="Upload raw .eml email file"
                type="file"
                accept=".eml,.msg,.txt,.mime"
                onChange={handleFileChange}
                className="hidden"
              />
            </label>
            <button
              type="submit"
              disabled={loading || !file}
              className={`w-full md:w-auto px-6 py-4 rounded-lg text-sm font-semibold flex items-center justify-center space-x-2 transition-colors ${
                loading || !file
                  ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/20'
              }`}
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Parsing Email...</span>
                </>
              ) : (
                <>
                  <FileCheck className="w-4 h-4" />
                  <span>Parse & Normalize</span>
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div className="mt-4 p-3 bg-red-950/40 border border-red-800/60 rounded-lg flex items-center space-x-2 text-xs text-red-400">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Results View */}
      {email && scanResult && (
        <div className="space-y-6">
          {/* Header Summary */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="flex flex-wrap items-center justify-between border-b border-gray-800 pb-4 mb-4 gap-2">
              <div className="flex items-center space-x-3">
                <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-mono font-medium">
                  {scanResult.status}
                </span>
                <span className="text-xs text-gray-400 font-mono">
                  Scan ID: #{scanResult.scan_id}
                </span>
                <span className="text-xs text-gray-500 font-mono truncate max-w-xs">
                  {scanResult.scan_uuid}
                </span>
              </div>
              <div className="text-xs text-gray-400 font-mono flex items-center space-x-1">
                <Clock className="w-3.5 h-3.5 text-gray-500" />
                <span>{new Date(scanResult.created_at).toLocaleTimeString()}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans">
              <div>
                <span className="text-gray-500 block">Subject:</span>
                <span className="text-sm font-semibold text-white">
                  {email.subject || '<No Subject>'}
                </span>
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

            {/* Warnings Alert Banner */}
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
              Overview & Hops ({email.received_hops.length})
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
              <span>Extracted URLs ({email.urls.length})</span>
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
                <div className="space-y-2">
                  {email.received_hops.map((hop) => (
                    <div
                      key={hop.hop_number}
                      className="p-3 bg-gray-950 rounded border border-gray-800 font-mono text-xs flex flex-col space-y-1"
                    >
                      <div className="flex items-center justify-between text-gray-400">
                        <span className="text-blue-400 font-bold">Hop #{hop.hop_number}</span>
                        <span>{hop.date || ''}</span>
                      </div>
                      <div className="text-gray-300">
                        From: <span className="text-white">{hop.from_host || 'unknown'}</span> [IP: {hop.ip || 'none'}]
                      </div>
                      <div className="text-gray-400 text-[11px] truncate">{hop.raw}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'urls' && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="px-6 py-3 border-b border-gray-800 bg-gray-950 text-xs font-semibold text-gray-400">
                Extracted Hyperlinks (Defanged)
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
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'attachments' && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="px-6 py-3 border-b border-gray-800 bg-gray-950 text-xs font-semibold text-gray-400">
                Attachment Forensics & Cryptographic Hashes
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
    </div>
  );
};
