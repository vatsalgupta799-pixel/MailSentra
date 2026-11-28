import React, { useState } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import { Scans } from './pages/Scans';
import { Alerts } from './pages/Alerts';
import { Audit } from './pages/Audit';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

  const handleSelectScan = (scanId: number) => {
    setSelectedScanId(scanId);
    setCurrentTab('scans');
  };

  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden font-sans">
      <Sidebar currentTab={currentTab} setCurrentTab={setCurrentTab} />
      <div className="flex-1 flex flex-col min-w-0">
        <Header />
        <main className="flex-1 overflow-y-auto p-8">
          {currentTab === 'dashboard' && (
            <Dashboard
              onSelectScan={handleSelectScan}
              onNavigateTab={setCurrentTab}
            />
          )}
          {currentTab === 'scans' && (
            <Scans
              initialScanId={selectedScanId}
              onClearInitialScan={() => setSelectedScanId(null)}
            />
          )}
          {currentTab === 'alerts' && (
            <Alerts
              onSelectScan={handleSelectScan}
              onNavigateTab={setCurrentTab}
            />
          )}
          {currentTab === 'audit' && <Audit />}
        </main>
      </div>
    </div>
  );
};

export default App;
