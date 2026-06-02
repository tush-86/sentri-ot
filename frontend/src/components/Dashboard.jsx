import React from 'react';
import {
  AlertTriangle, Building2, CheckCircle2, Cpu, Database,
  Layers, Server, Shield, ShieldAlert, Wifi
} from 'lucide-react';
import {
  Bar, BarChart, Cell,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid
} from 'recharts';

const severityColors = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#22c55e'
};

const zoneColors = ['#22c55e', '#06b6d4', '#f59e0b', '#f97316', '#ef4444'];

function StatCard({ icon: Icon, label, value, accent, subtitle }) {
  return (
    <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-5 shadow-2xl transition hover:border-slate-700">
      <div className="mb-4 flex items-center justify-between">
        <span className="text-sm text-slate-400">{label}</span>
        <Icon className={`h-5 w-5 ${accent || 'text-emerald-400'}`} />
      </div>
      <p className="text-3xl font-black text-white">{value ?? '--'}</p>
      {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
    </div>
  );
}

function EmptyState({ label }) {
  return <div className="flex h-64 items-center justify-center rounded-3xl border border-slate-800 bg-slate-900/70 text-slate-500">{label}</div>;
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm shadow-2xl">
      {label && <p className="mb-1 font-bold text-white">{label}</p>}
      {payload.map((entry) => (
        <p key={entry.name} style={{ color: entry.color }}>
          {entry.name}: <strong>{entry.value}</strong>
        </p>
      ))}
    </div>
  );
}

export default function Dashboard({ summary, loading, error }) {
  if (loading) return <EmptyState label="Loading BMS telemetry..." />;
  if (error) return <EmptyState label={error} />;
  if (!summary) return <EmptyState label="No scan summary available. Run a scan to populate the dashboard." />;

  const totalDevices = summary.total_assets ?? summary.total_devices ?? 0;
  const bacnetObjects = summary.bacnet_objects ?? summary.objects ?? 0;
  const complianceScore = summary.compliance_score ?? summary.overall_score ?? 0;
  const criticalVulns = summary.critical_vulnerabilities ?? 0;
  const riskLevel = summary.risk_level ?? (criticalVulns > 10 ? 'Critical' : criticalVulns > 3 ? 'High' : 'Moderate');

  const riskLevelColor = {
    Critical: 'text-red-400', High: 'text-orange-400',
    Moderate: 'text-amber-400', Low: 'text-emerald-400'
  }[riskLevel] || 'text-slate-400';

  const protocolData = Object.entries(summary.protocols_discovered || {}).map(([name, value]) => ({ name, value }));
  if (!protocolData.length) protocolData.push({ name: 'BACnet', value: 0 });

  const deviceTypesData = Object.entries(summary.device_types || {}).map(([name, value]) => ({ name, value }));
  if (!deviceTypesData.length) {
    deviceTypesData.push(
      { name: 'Controllers', value: 0 },
      { name: 'Sensors', value: 0 },
      { name: 'Gateways', value: 0 },
      { name: 'Workstations', value: 0 }
    );
  }

  const zoneData = Object.entries(summary.zone_distribution || summary.zones_discovered || {}).map(([name, value]) => ({ name, value }));
  if (!zoneData.length) {
    zoneData.push(
      { name: 'Zone 0', value: 0 },
      { name: 'Zone 1', value: 0 },
      { name: 'Zone 2', value: 0 },
      { name: 'Zone 3', value: 0 },
      { name: 'DMZ', value: 0 }
    );
  }

  const vendorData = Object.entries(summary.top_vendors || {}).map(([name, value]) => ({ name, value })).slice(0, 8);
  if (!vendorData.length) {
    vendorData.push(
      { name: 'Siemens', value: 0 },
      { name: 'Johnson Controls', value: 0 },
      { name: 'Honeywell', value: 0 },
      { name: 'Schneider', value: 0 }
    );
  }

  const severityData = Object.entries(summary.vulnerabilities_by_severity || {}).map(([name, value]) => ({ name, value }));
  if (!severityData.length) {
    severityData.push(
      { name: 'Critical', value: 0 },
      { name: 'High', value: 0 },
      { name: 'Medium', value: 0 },
      { name: 'Low', value: 0 }
    );
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm uppercase tracking-[0.35em] text-emerald-300">BMS security posture</p>
        <h2 className="text-4xl font-black text-white">Sentri OT Dashboard</h2>
        {summary.generated_at && (
          <p className="mt-1 text-sm text-slate-500">
            Last updated: {new Date(summary.generated_at).toLocaleString()}
          </p>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-5">
        <StatCard icon={Server} label="Total Devices" value={totalDevices} accent="text-cyan-400" subtitle="BACnet & Modbus assets" />
        <StatCard icon={Database} label="BACnet Objects" value={bacnetObjects} accent="text-emerald-400" subtitle="Points & devices" />
        <StatCard icon={CheckCircle2} label="Compliance Score" value={`${complianceScore}%`} accent="text-emerald-300" subtitle="DESC ICS/OT + IEC 62443" />
        <StatCard icon={ShieldAlert} label="Critical Vulns" value={criticalVulns} accent="text-red-400" subtitle="Requires immediate action" />
        <StatCard icon={Shield} label="Risk Level" value={riskLevel} accent={riskLevelColor} subtitle="Overall posture" />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-white">
            <Wifi className="h-5 w-5 text-cyan-400" /> Protocol Distribution
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={protocolData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={3}>
                {protocolData.map((entry, i) => (
                  <Cell key={entry.name} fill={['#22c55e', '#06b6d4', '#f59e0b', '#a855f7', '#ef4444'][i % 5]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-3 flex flex-wrap gap-2">
            {protocolData.filter(d => d.value > 0).map((item, i) => (
              <span key={item.name} className="flex items-center gap-1.5 rounded-full bg-slate-950/70 px-3 py-1 text-xs text-slate-300">
                <span className="h-2 w-2 rounded-full" style={{ background: ['#22c55e', '#06b6d4', '#f59e0b', '#a855f7', '#ef4444'][i % 5] }} />
                {item.name}: {item.value}
              </span>
            ))}
          </div>
        </div>

        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-white">
            <Building2 className="h-5 w-5 text-emerald-400" /> Device Types
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={deviceTypesData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis type="number" stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} width={90} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" fill="#22c55e" radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-white">
            <Layers className="h-5 w-5 text-cyan-400" /> Zone Distribution
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={zoneData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <YAxis stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {zoneData.map((entry, i) => (
                  <Cell key={entry.name} fill={zoneColors[i % zoneColors.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-white">
            <Server className="h-5 w-5 text-amber-400" /> Top Vendors
          </h3>
          <ResponsiveContainer width="100%" height={Math.max(160, vendorData.length * 32)}>
            <BarChart data={vendorData} layout="vertical" margin={{ left: 0, right: 10, top: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} width={120} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" fill="#f59e0b" radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-white">
            <AlertTriangle className="h-5 w-5 text-red-400" /> Vulnerabilities by Severity
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={95} paddingAngle={3}>
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={severityColors[entry.name] || '#64748b'} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-2">
            {severityData.filter(d => d.value > 0).map((item) => (
              <div key={item.name} className="flex items-center justify-between rounded-xl bg-slate-950/70 px-3 py-2 text-sm text-slate-300">
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full" style={{ background: severityColors[item.name] }} />
                  {item.name}
                </span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
