import React, { useEffect, useState } from 'react';
import api from '../services/api';
import { HealthStatus } from '../types';
import { CheckCircle2, AlertTriangle, Radio } from 'lucide-react';

export const Header: React.FC = () => {
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const res = await api.get<HealthStatus>('/health');
        setHealth(res.data);
      } catch {
        setHealth({
          status: 'OFFLINE',
          service: 'MailSentra Backend',
          version: '1.0.0-phase1',
          environment: 'development',
          database_connected: false,
        });
      }
    };
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 bg-gray-900 border-b border-gray-800 flex items-center justify-between px-6">
      <div className="flex items-center space-x-3">
        <span className="text-sm font-semibold text-gray-300">Security Operations Console</span>
        <span className="text-gray-600">/</span>
        <span className="text-xs font-mono text-gray-500">Threat Defense Layer</span>
      </div>

      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 px-3 py-1 bg-gray-950 rounded-full border border-gray-800 text-xs">
          <Radio className="w-3.5 h-3.5 text-blue-400 animate-pulse" />
          <span className="text-gray-400">Backend:</span>
          {health?.database_connected ? (
            <span className="text-emerald-400 font-medium flex items-center space-x-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>ONLINE (DB Connected)</span>
            </span>
          ) : (
            <span className="text-amber-400 font-medium flex items-center space-x-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>STANDBY</span>
            </span>
          )}
        </div>

        <div className="text-xs text-gray-400 border-l border-gray-800 pl-4">
          Environment: <span className="font-mono text-gray-300">Development</span>
        </div>
      </div>
    </header>
  );
};
