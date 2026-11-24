import React from 'react';
import { Bell } from 'lucide-react';

export const Alerts: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">Security Threat Alerts</h2>
          <p className="text-xs text-gray-400">High-priority incident dispatch and SOC analyst notifications</p>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
        <div className="w-12 h-12 bg-amber-600/10 text-amber-400 rounded-full flex items-center justify-center mx-auto mb-4">
          <Bell className="w-6 h-6" />
        </div>
        <h3 className="text-sm font-semibold text-white mb-1">Alert Dispatch Subsystem Ready</h3>
        <p className="text-xs text-gray-400 max-w-md mx-auto mb-4">
          The Alert relational entity model and notification interfaces are provisioned. Dispatch triggers will execute when risk thresholds are calculated in Part 4.
        </p>
      </div>
    </div>
  );
};
