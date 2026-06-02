import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { AlertCircle } from 'lucide-react';
import './index.css';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import AssetInventory from './components/AssetInventory';
import ComplianceReport from './components/ComplianceReport';
import Alerts from './components/Alerts';
import { api } from './lib/api';

const SentriContext = createContext(null);

function useSentri() {
  const value = useContext(SentriContext);
  if (!value) throw new Error('useSentri must be used inside SentriProvider');
  return value;
}

function SentriProvider({ children }) {
  const [summary, setSummary] = useState(null);
  const [scan, setScan] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [alerts, setAlerts] = useState({ alerts: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [scanStatus, setScanStatus] = useState({ status: 'idle', progress: 0, message: 'Ready to scan' });
  const [scanHistory, setScanHistory] = useState([]);
  const [assetCount, setAssetCount] = useState(null);

  const refreshData = useCallback(async () => {
    setError('');
    try {
      const [summaryData, scanData, complianceData, alertsData, historyData] = await Promise.all([
        api.getSummary().catch(() => null),
        api.getLatestScan().catch(() => null),
        api.getCompliance().catch(() => null),
        api.getAlerts({ page: 1, per_page: 50 }).catch(() => ({ alerts: [], total: 0 })),
        api.getScanHistory().catch(() => ({ history: [] })),
      ]);
      setSummary(summaryData);
      setScan(scanData);
      setCompliance(complianceData);
      setAlerts(alertsData);
      setScanHistory((historyData || {}).history || []);
      if (scanData?.assets) {
        setAssetCount(scanData.assets.length);
      } else if (summaryData?.total_assets) {
        setAssetCount(summaryData.total_assets);
      }
    } catch (err) {
      setError(err.message || 'Unable to load Sentri OT data.');
    }
  }, []);

  useEffect(() => {
    refreshData()
      .catch((err) => setError(err.message || 'Unable to load Sentri OT data.'))
      .finally(() => setLoading(false));
  }, [refreshData]);

  const runScan = useCallback(async () => {
    setError('');
    try {
      await api.startScan();
      setScanStatus({ status: 'running', progress: 5, message: 'Scan queued' });
    } catch (err) {
      setError(err.message || 'Unable to start scan.');
    }
  }, []);

  useEffect(() => {
    if (scanStatus.status !== 'running') return undefined;

    const interval = window.setInterval(async () => {
      try {
        const status = await api.getScanStatus();
        setScanStatus(status);
        if (status.status === 'complete') {
          window.clearInterval(interval);
          setLoading(true);
          await refreshData();
          setLoading(false);
        }
      } catch (err) {
        setError(err.message || 'Scan status polling failed.');
        window.clearInterval(interval);
      }
    }, 800);

    return () => window.clearInterval(interval);
  }, [refreshData, scanStatus.status]);

  const contextValue = useMemo(
    () => ({ summary, scan, compliance, alerts, loading, error, scanStatus, scanHistory, assetCount, runScan }),
    [summary, scan, compliance, alerts, loading, error, scanStatus, scanHistory, assetCount, runScan]
  );
  return <SentriContext.Provider value={contextValue}>{children}</SentriContext.Provider>;
}

function MainContent({ activeView }) {
  const { summary, scan, compliance, alerts, loading, error } = useSentri();
  if (activeView === 'assets') return <AssetInventory scan={scan} loading={loading} error={error} />;
  if (activeView === 'compliance') return <ComplianceReport compliance={compliance} loading={loading} error={error} />;
  if (activeView === 'alerts') return <Alerts alerts={alerts} loading={loading} error={error} />;
  return <Dashboard summary={summary} loading={loading} error={error} />;
}

function Shell() {
  const [activeView, setActiveView] = useState('dashboard');
  const { scanStatus, runScan, scanHistory, assetCount, error } = useSentri();

  return (
    <div className="flex min-h-screen text-slate-100">
      <Sidebar activeView={activeView} onNavigate={setActiveView} onRunScan={runScan} scanStatus={scanStatus} scanHistory={scanHistory} deviceCount={assetCount} />
      <main className="min-w-0 flex-1 p-6 lg:p-10">
        {error && (
          <div className="mb-6 flex items-center gap-3 rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-red-200">
            <AlertCircle className="h-5 w-5" />
            <span>{error}</span>
          </div>
        )}
        <MainContent activeView={activeView} />
      </main>
    </div>
  );
}

function App() {
  return (
    <React.StrictMode>
      <SentriProvider>
        <Shell />
      </SentriProvider>
    </React.StrictMode>
  );
}

const rootElement = document.getElementById('root');
if (rootElement) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(<App />);
}

export default App;
export { SentriContext, useSentri };
