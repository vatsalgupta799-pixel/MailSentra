import React from 'react';
import { FileText } from 'lucide-react';

export const Audit: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">Immutable Security Audit Trail</h2>
          <p className="text-xs text-gray-400">Tamper-evident record of administrative and analyst actions</p>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
        <div className="w-12 h-12 bg-emerald-600/10 text-emerald-400 rounded-full flex items-center justify-center mx-auto mb-4">
          <FileText className="w-6 h-6" />
        </div>
        <h3 className="text-sm font-semibold text-white mb-1">Append-Only Audit Engine Active</h3>
        <p className="text-xs text-gray-400 max-w-md mx-auto mb-4">
          The AuditRecord model and AuditLogger are active. All login events, system modifications, and triage actions are tracked to this append-only log.
        </p>
      </div>
    </div>
  );
};
