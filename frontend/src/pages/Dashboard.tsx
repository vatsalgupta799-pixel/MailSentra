import React from 'react';
import { Shield, CheckCircle2, Lock, Cpu, Server } from 'lucide-react';

export const Dashboard: React.FC = () => {
  const architecturalModules = [
    { id: 1, name: 'Email Ingestion Module', status: 'Contract Defined', tier: 'Foundation' },
    { id: 2, name: 'Email Parsing & Normalization', status: 'Contract Defined', tier: 'Foundation' },
    { id: 3, name: 'Sender Identity Verification', status: 'Contract Defined', tier: 'Detection' },
    { id: 4, name: 'SPF, DKIM & DMARC Analysis', status: 'Contract Defined', tier: 'Detection' },
    { id: 5, name: 'URL Security Analysis', status: 'Contract Defined', tier: 'Detection' },
    { id: 6, name: 'Attachment Security Module', status: 'Contract Defined', tier: 'Detection' },
    { id: 7, name: 'Social Engineering & BEC Engine', status: 'Contract Defined', tier: 'Detection' },
    { id: 8, name: 'Threat Intelligence Integration', status: 'Contract Defined', tier: 'Enrichment' },
    { id: 9, name: 'Risk Scoring & Decision Engine', status: 'Contract Defined', tier: 'Arbitration' },
    { id: 10, name: 'Alert & Notification Module', status: 'Contract Defined', tier: 'Dispatch' },
    { id: 11, name: 'Admin Dashboard & Telemetry', status: 'Active (Shell)', tier: 'Presentation' },
    { id: 12, name: 'Authentication & RBAC', status: 'Implemented', tier: 'Security' },
    { id: 13, name: 'Audit Logging Module', status: 'Implemented', tier: 'Compliance' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-gradient-to-r from-blue-950/40 via-gray-900 to-gray-900 border border-blue-900/30 rounded-xl">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-white mb-1">MailSentra Security Architecture (Part 1 Foundation)</h2>
            <p className="text-sm text-gray-400">
              Technical foundation, strictly typed data contracts, and enterprise modular structure are initialized.
            </p>
          </div>
          <div className="flex items-center space-x-2 px-3 py-1.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono rounded-lg">
            <Cpu className="w-4 h-4" />
            <span>Architecture v1.0 Ready</span>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-gray-400">Core Modules</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">13 / 13</div>
          <p className="text-xs text-gray-500 mt-1">Contracts & Interfaces Defined</p>
        </div>

        <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-gray-400">Database Engine</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white">Async SQLAlchemy</div>
          <p className="text-xs text-gray-500 mt-1">SQLite Dev / PostgreSQL Ready</p>
        </div>

        <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-gray-400">Security Model</span>
            <Lock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white">RBAC + JWT</div>
          <p className="text-xs text-gray-500 mt-1">Bcrypt / Argon2id Hashing</p>
        </div>

        <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-gray-400">Part 1 Verification</span>
            <Shield className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">PASSED</div>
          <p className="text-xs text-gray-500 mt-1">0 Mock APIs • Pure Foundation</p>
        </div>
      </div>

      {/* Module Matrix */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">13 Core Architectural Subsystems</h3>
          <span className="text-xs text-gray-500 font-mono">MailSentra Modular Engine</span>
        </div>
        <div className="divide-y divide-gray-800/60">
          {architecturalModules.map((mod) => (
            <div key={mod.id} className="px-6 py-3.5 flex items-center justify-between hover:bg-gray-850/50 transition-colors">
              <div className="flex items-center space-x-3">
                <span className="text-xs font-mono text-gray-500 w-6">#{mod.id}</span>
                <span className="text-sm font-medium text-gray-200">{mod.name}</span>
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400 font-mono">
                  {mod.tier}
                </span>
                <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${
                  mod.status.includes('Active')
                    ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                    : mod.status.includes('Implemented')
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'bg-gray-800 text-gray-300'
                }`}>
                  {mod.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
