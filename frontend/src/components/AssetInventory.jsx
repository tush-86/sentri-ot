import React, { useMemo, useState } from 'react';
import {
  ArrowDownUp, Building2, ChevronDown, ChevronLeft, ChevronRight, Cpu,
  Database, MonitorCog, RadioTower, Search, ShieldAlert, X
} from 'lucide-react';

const iconMap = { Cpu, Building2, RadioTower, MonitorCog, Database };

const badgeStyles = {
  Critical: 'bg-red-500/15 text-red-300 border-red-500/30',
  High: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  Medium: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  Low: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
};

function Badge({ value }) {
  return (
    <span className={`inline-block rounded-full border px-3 py-1 text-xs font-bold ${badgeStyles[value] || 'border-slate-700 bg-slate-800 text-slate-300'}`}>
      {value}
    </span>
  );
}

const protocolOptions = ['BACnet', 'Modbus', 'EtherNet/IP', 'Profinet', 'S7', 'DNP3', 'OPC UA'];
const zoneOptions = ['Zone 0', 'Zone 1', 'Zone 2', 'Zone 3', 'DMZ'];
const criticalityOptions = ['Critical', 'High', 'Medium', 'Low'];

function FilterChip({ label, active, onClick }) {
  const colorMap = {
    Critical: 'border-red-500/40 bg-red-500/15 text-red-200',
    High: 'border-orange-500/40 bg-orange-500/15 text-orange-200',
    Medium: 'border-amber-500/40 bg-amber-500/15 text-amber-200',
    Low: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200',
    BACnet: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200',
    Modbus: 'border-cyan-500/40 bg-cyan-500/15 text-cyan-200',
  };
  const activeStyle = colorMap[label] || 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200';
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-xs font-semibold transition ${
        active ? activeStyle : 'border-slate-700 bg-slate-800/50 text-slate-400 hover:border-slate-600 hover:text-slate-300'
      }`}
    >
      {label}
    </button>
  );
}

const ITEMS_PER_PAGE = 50;

export default function AssetInventory({ scan, loading, error }) {
  const [expanded, setExpanded] = useState({});
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [zoneFilter, setZoneFilter] = useState('');
  const [criticalityFilter, setCriticalityFilter] = useState('');
  const [sortField, setSortField] = useState(null);
  const [sortDirection, setSortDirection] = useState('asc');
  const [page, setPage] = useState(1);

  if (loading) return <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-10 text-slate-400">Loading asset inventory...</div>;
  if (error) return <div className="rounded-3xl border border-red-900/60 bg-red-950/30 p-10 text-red-200">{error}</div>;

  const assets = scan?.assets || [];

  const filtered = useMemo(() => {
    let result = [...assets];

    if (search) {
      const q = search.toLowerCase();
      result = result.filter(a =>
        (a.hostname && a.hostname.toLowerCase().includes(q)) ||
        (a.ip && a.ip.includes(q))
      );
    }
    if (protocolFilter) result = result.filter(a => a.protocol === protocolFilter);
    if (zoneFilter) result = result.filter(a => a.segmentation_zone === zoneFilter);
    if (criticalityFilter) result = result.filter(a => a.criticality === criticalityFilter);

    if (sortField) {
      result.sort((a, b) => {
        let aVal = a[sortField];
        let bVal = b[sortField];
        if (sortField === 'vulns') {
          aVal = (a.vulnerabilities?.length || 0);
          bVal = (b.vulnerabilities?.length || 0);
        }
        if (sortField === 'hostname') {
          aVal = (a.hostname || '').toLowerCase();
          bVal = (b.hostname || '').toLowerCase();
        }
        if (sortField === 'criticality') {
          const order = { Critical: 4, High: 3, Medium: 2, Low: 1 };
          aVal = order[a.criticality] || 0;
          bVal = order[b.criticality] || 0;
        }
        if (sortField === 'risk') {
          aVal = (a.risk_level || '').toLowerCase();
          bVal = (b.risk_level || '').toLowerCase();
        }
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
    }

    return result;
  }, [assets, search, protocolFilter, zoneFilter, criticalityFilter, sortField, sortDirection]);

  const totalFiltered = filtered.length;
  const totalPages = Math.max(1, Math.ceil(totalFiltered / ITEMS_PER_PAGE));
  const safePage = Math.min(page, totalPages);
  const startIndex = (safePage - 1) * ITEMS_PER_PAGE;
  const pageItems = filtered.slice(startIndex, startIndex + ITEMS_PER_PAGE);

  const criticalCount = filtered.filter(a => a.criticality === 'Critical').length;
  const highRiskCount = filtered.filter(a => a.risk_level === 'High' || a.risk_level === 'Critical').length;

  function handleSort(field) {
    if (sortField === field) {
      setSortDirection(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  }

  function SortHeader({ field, children }) {
    const active = sortField === field;
    return (
      <button
        type="button"
        onClick={() => handleSort(field)}
        className="flex items-center gap-1 text-xs uppercase tracking-wider text-slate-500 hover:text-slate-300 transition"
      >
        {children}
        <ArrowDownUp className={`h-3 w-3 ${active ? 'text-emerald-400' : 'opacity-40'}`} />
      </button>
    );
  }

  return (
    <section className="space-y-6">
      {/* Header */}
      <div>
        <p className="text-sm uppercase tracking-[0.35em] text-cyan-300">Discovery</p>
        <h2 className="text-4xl font-black text-white">Asset Map</h2>
        <p className="mt-2 text-slate-400">
          Latest scan: {scan?.generated_at ? new Date(scan.generated_at).toLocaleString() : 'N/A'}
          {totalFiltered > 0 && ` · ${totalFiltered} device${totalFiltered !== 1 ? 's' : ''} discovered`}
        </p>
      </div>

      {/* Search + Summary bar */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by hostname or IP..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full rounded-2xl border border-slate-700 bg-slate-900 py-3 pl-10 pr-4 text-sm text-white placeholder-slate-500 outline-none transition focus:border-emerald-400/50 focus:ring-1 focus:ring-emerald-400/20"
          />
        </div>
        <div className="text-sm text-slate-400">
          Showing {startIndex + 1}-{Math.min(startIndex + ITEMS_PER_PAGE, totalFiltered)} of {totalFiltered} assets
          {criticalCount > 0 && <span className="ml-2 text-red-400">| {criticalCount} Critical</span>}
          {highRiskCount > 0 && <span className="ml-2 text-orange-400">| {highRiskCount} High Risk</span>}
        </div>
      </div>

      {/* Filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Protocol:</span>
        {protocolOptions.map(p => (
          <FilterChip key={p} label={p} active={protocolFilter === p} onClick={() => {
            setProtocolFilter(protocolFilter === p ? '' : p);
            setPage(1);
          }} />
        ))}
        <span className="ml-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Zone:</span>
        {zoneOptions.map(z => (
          <FilterChip key={z} label={z} active={zoneFilter === z} onClick={() => {
            setZoneFilter(zoneFilter === z ? '' : z);
            setPage(1);
          }} />
        ))}
        <span className="ml-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Criticality:</span>
        {criticalityOptions.map(c => (
          <FilterChip key={c} label={c} active={criticalityFilter === c} onClick={() => {
            setCriticalityFilter(criticalityFilter === c ? '' : c);
            setPage(1);
          }} />
        ))}
        {(search || protocolFilter || zoneFilter || criticalityFilter) && (
          <button
            type="button"
            onClick={() => { setSearch(''); setProtocolFilter(''); setZoneFilter(''); setCriticalityFilter(''); setPage(1); }}
            className="flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800/50 px-3 py-1 text-xs text-slate-400 hover:text-white transition"
          >
            <X className="h-3 w-3" /> Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-3xl border border-slate-800 bg-slate-900/70">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left">
            <thead className="bg-slate-950/80 text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-5 py-4"><SortHeader field="hostname">Asset</SortHeader></th>
                <th className="px-5 py-4">IP</th>
                <th className="px-5 py-4"><SortHeader field="protocol">Protocol</SortHeader></th>
                <th className="px-5 py-4">Zone</th>
                <th className="px-5 py-4"><SortHeader field="criticality">Criticality</SortHeader></th>
                <th className="px-5 py-4"><SortHeader field="risk">Risk</SortHeader></th>
                <th className="px-5 py-4"><SortHeader field="vulns">Vulns</SortHeader></th>
                <th className="px-5 py-4">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {pageItems.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-5 py-12 text-center text-slate-500">
                    No assets match the current filters.
                  </td>
                </tr>
              ) : (
                pageItems.map((asset) => {
                  const Icon = iconMap[asset.icon] || Cpu;
                  const isOpen = expanded[asset.id] || false;
                  const vulnCount = asset.vulnerabilities?.length || 0;
                  const pointsCount = asset.points_count ?? asset.objects_count ?? 0;
                  return (
                    <tr key={asset.id} className="align-top transition hover:bg-slate-800/40">
                      <td colSpan={8} className="p-0">
                        <button
                          type="button"
                          onClick={() => setExpanded((cur) => ({ ...cur, [asset.id]: !cur[asset.id] }))}
                          className="grid w-full grid-cols-[1.8fr_1.2fr_1fr_1fr_1fr_0.8fr_0.6fr_1fr] items-center gap-2 px-5 py-4 text-left"
                        >
                          <span className="flex items-center gap-3">
                            <span className="shrink-0 rounded-xl border border-cyan-400/30 bg-cyan-400/10 p-2">
                              <Icon className="h-5 w-5 text-cyan-300" />
                            </span>
                            <span className="min-w-0">
                              <strong className="block truncate text-white">{asset.hostname}</strong>
                              <small className="text-slate-500">{asset.type}</small>
                            </span>
                          </span>
                          <span className="font-mono text-sm text-slate-300">{asset.ip}</span>
                          <span className="text-sm text-slate-300">{asset.protocol}</span>
                          <span className="text-sm text-slate-300">{asset.segmentation_zone || 'Unknown'}</span>
                          <span><Badge value={asset.criticality} /></span>
                          <span><Badge value={asset.risk_level} /></span>
                          <span className="flex items-center gap-1.5 text-sm text-slate-300">
                            {vulnCount}
                            <ChevronDown className={`h-4 w-4 transition ${isOpen ? 'rotate-180' : ''}`} />
                          </span>
                          <span className="text-xs text-slate-500">
                            {asset.last_seen ? new Date(asset.last_seen).toLocaleDateString() : '--'}
                          </span>
                        </button>
                        {isOpen && (
                          <div className="border-t border-slate-800 bg-slate-950/70 px-8 py-5">
                            <div className="mb-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
                                <p className="mb-2 text-xs uppercase tracking-[0.25em] text-slate-500">Device Posture</p>
                                <p className="text-sm text-slate-300">Firmware: <span className="font-semibold text-white">{asset.firmware_version || 'N/A'}</span></p>
                                <p className="text-sm text-slate-300">Auth: <span className="font-semibold text-white">{asset.authentication || 'N/A'}</span></p>
                                <p className="text-sm text-slate-300">Status: <span className="font-semibold text-white">{asset.security_status || 'Unknown'}</span></p>
                              </div>
                              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
                                <p className="mb-2 text-xs uppercase tracking-[0.25em] text-slate-500">BACnet Objects</p>
                                <p className="text-2xl font-black text-white">{pointsCount}</p>
                                <p className="text-xs text-slate-500">Points monitored</p>
                              </div>
                              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
                                <p className="mb-2 text-xs uppercase tracking-[0.25em] text-slate-500">Protocol</p>
                                <p className="text-sm text-white font-semibold">{asset.protocol}</p>
                                {asset.vendor && <p className="text-xs text-slate-500">{asset.vendor}</p>}
                              </div>
                              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
                                <p className="mb-2 text-xs uppercase tracking-[0.25em] text-slate-500">MAC / Device ID</p>
                                <p className="font-mono text-xs text-slate-300">{asset.mac_address || asset.device_id || 'N/A'}</p>
                                {asset.subnet && <p className="text-xs text-slate-500">Subnet: {asset.subnet}</p>}
                              </div>
                            </div>

                            <h4 className="mb-3 flex items-center gap-2 font-bold text-white">
                              <ShieldAlert className="h-4 w-4 text-amber-300" /> Vulnerabilities
                            </h4>
                            {vulnCount > 0 ? (
                              <div className="grid gap-3 md:grid-cols-2">
                                {asset.vulnerabilities.map((vuln) => (
                                  <div key={`${asset.id}-${vuln.id}`} className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
                                    <div className="mb-2 flex items-center justify-between">
                                      <strong className="font-mono text-sm text-white">{vuln.id}</strong>
                                      <Badge value={vuln.severity} />
                                    </div>
                                    <p className="text-sm text-slate-300">{vuln.title}</p>
                                    {vuln.description && <p className="mt-2 text-xs text-slate-400">{vuln.description}</p>}
                                    {vuln.recommendation && (
                                      <p className="mt-2 text-xs text-emerald-400">Recommendation: {vuln.recommendation}</p>
                                    )}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-sm text-slate-500">No vulnerabilities discovered for this asset.</p>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/70 px-5 py-3">
          <span className="text-sm text-slate-400">
            Page {safePage} of {totalPages}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={safePage <= 1}
              onClick={() => setPage(safePage - 1)}
              className="flex items-center gap-1 rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronLeft className="h-4 w-4" /> Prev
            </button>

            {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
              let pageNum;
              if (totalPages <= 7) {
                pageNum = i + 1;
              } else if (safePage <= 4) {
                pageNum = i + 1;
              } else if (safePage >= totalPages - 3) {
                pageNum = totalPages - 6 + i;
              } else {
                pageNum = safePage - 3 + i;
              }
              return (
                <button
                  key={pageNum}
                  type="button"
                  onClick={() => setPage(pageNum)}
                  className={`min-w-[2.25rem] rounded-xl border px-3 py-2 text-sm font-medium transition ${
                    safePage === pageNum
                      ? 'border-emerald-400/40 bg-emerald-400/15 text-emerald-200'
                      : 'border-slate-700 bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200'
                  }`}
                >
                  {pageNum}
                </button>
              );
            })}

            <button
              type="button"
              disabled={safePage >= totalPages}
              onClick={() => setPage(safePage + 1)}
              className="flex items-center gap-1 rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
