import React, { useState } from 'react';
import {
  Activity, ChevronDown, Clock, History, LayoutDashboard,
  Network, Radar, ShieldAlert, ShieldCheck, Server
} from 'lucide-react';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'assets', label: 'Asset Map', icon: Network },
  { id: 'compliance', label: 'Compliance', icon: ShieldCheck },
  { id: 'alerts', label: 'Alerts', icon: ShieldAlert },
];

function ScanHistoryDropdown({ history }) {
  const [open, setOpen] = useState(false);
  if (!history || history.length === 0) return null;
  const recent = history.slice(0, 5);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between rounded-xl border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs text-slate-400 hover:text-slate-300 transition"
      >
        <span className="flex items-center gap-1.5">
          <History className="h-3.5 w-3.5" />
          Recent scans
        </span>
        <ChevronDown className={`h-3 w-3 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="absolute bottom-full left-0 right-0 mb-2 rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl p-2 space-y-1 z-20">
          {recent.map((scan, i) => (
            <div key={scan.scan_id || scan.id || i} className="rounded-xl bg-slate-950/80 px-3 py-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">
                  {scan.timestamp || scan.generated_at
                    ? new Date(scan.timestamp || scan.generated_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                    : 'N/A'}
                </span>
                <span className={`text-xs font-semibold ${
                  scan.status === 'complete' ? 'text-emerald-400' :
                  scan.status === 'running' ? 'text-cyan-400' :
                  scan.status === 'failed' ? 'text-red-400' : 'text-slate-500'
                }`}>
                  {scan.status || 'unknown'}
                </span>
              </div>
              {scan.devices_found != null && (
                <p className="text-xs text-slate-500 mt-0.5">{scan.devices_found} devices</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Sidebar({ activeView, onNavigate, onRunScan, scanStatus, deviceCount, scanHistory }) {
  const isRunning = scanStatus?.status === 'running';

  return (
    <aside className="flex min-h-screen w-72 flex-col border-r border-slate-800 bg-slate-950/90 p-6 backdrop-blur">
      {/* Brand */}
      <div className="mb-8 flex items-center gap-3">
        <div className="rounded-2xl border border-emerald-400/40 bg-emerald-400/10 p-3 shadow-glow">
          <Radar className="h-7 w-7 text-emerald-400" />
        </div>
        <div>
          <h1 className="text-xl font-black tracking-wide text-white">Sentri OT</h1>
          <p className="text-xs uppercase tracking-[0.3em] text-emerald-300">Cyber-physical</p>
        </div>
      </div>

      {/* Device count badge */}
      {deviceCount !== null && deviceCount !== undefined && (
        <div className="mb-6 flex items-center gap-2 rounded-2xl border border-slate-800 bg-slate-900/70 px-4 py-3">
          <Server className="h-4 w-4 text-cyan-400" />
          <span className="text-sm text-slate-300">
            <strong className="text-white">{deviceCount}</strong> devices
          </span>
        </div>
      )}

      {/* Navigation */}
      <nav className="space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const selected = activeView === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onNavigate(item.id)}
              className={`flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left transition ${
                selected
                  ? 'border border-emerald-400/40 bg-emerald-400/10 text-emerald-200 shadow-glow'
                  : 'border border-transparent text-slate-400 hover:border-slate-700 hover:bg-slate-900 hover:text-slate-100'
              }`}
            >
              <Icon className="h-5 w-5" />
              <span className="font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Spacer */}
      <div className="mt-6 space-y-3">
        {/* Scan status */}
        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="mb-3 flex items-center gap-2 text-sm text-slate-300">
            <Activity className={`h-4 w-4 ${isRunning ? 'animate-pulse text-emerald-400' : 'text-slate-500'}`} />
            <span className={isRunning ? 'text-emerald-200' : ''}>
              {scanStatus?.message || 'Ready'}
            </span>
          </div>
          {isRunning && (
            <div className="mb-3 h-2 rounded-full bg-slate-800">
              <div
                className="h-2 rounded-full bg-emerald-400 transition-all"
                style={{ width: `${scanStatus.progress || 0}%` }}
              />
            </div>
          )}
          <button
            type="button"
            onClick={onRunScan}
            disabled={isRunning}
            className="w-full rounded-2xl bg-emerald-400 px-4 py-3 font-bold text-slate-950 transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {isRunning ? 'Scanning...' : 'Run New Scan'}
          </button>
        </div>

        {/* Scan history dropdown */}
        <ScanHistoryDropdown history={scanHistory} />
      </div>

      {/* Footer / Version */}
      <div className="mt-auto pt-6 border-t border-slate-800">
        <div className="flex items-center justify-between text-xs text-slate-600">
          <span className="flex items-center gap-1">
            <Radar className="h-3 w-3" />
            v2.0.0
          </span>
          <span>BMS Security</span>
        </div>
      </div>
    </aside>
  );
}
