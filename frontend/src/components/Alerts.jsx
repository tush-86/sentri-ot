import React, { useState } from 'react';
import {
  Check, ChevronLeft, ChevronRight, CircleDot, Filter,
  ShieldAlert, ShieldCheck
} from 'lucide-react';
import { api } from '../lib/api';

const severityStyles = {
  Critical: 'border-red-500/30 bg-red-500/10 text-red-300',
  High: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
  Medium: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  Low: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  Info: 'border-slate-600/30 bg-slate-800/70 text-slate-300',
};

const severityColors = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#22c55e',
  Info: '#64748b',
};

const severityOptions = ['All', 'Critical', 'High', 'Medium', 'Low'];

const ITEMS_PER_PAGE = 20;

function AlertBadge({ severity }) {
  return (
    <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-black ${severityStyles[severity] || severityStyles.Info}`}>
      <CircleDot className="h-3.5 w-3.5" />
      {severity}
    </span>
  );
}

export default function Alerts({ alerts, loading, error }) {
  const [severityFilter, setSeverityFilter] = useState('All');
  const [page, setPage] = useState(1);
  const [acknowledgedIds, setAcknowledgedIds] = useState(new Set());
  const [acknowledging, setAcknowledging] = useState(new Set());
  const [ackError, setAckError] = useState('');

  if (loading) return <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-10 text-slate-400">Loading alert feed...</div>;
  if (error) return <div className="rounded-3xl border border-red-900/60 bg-red-950/30 p-10 text-red-200">{error}</div>;

  const allAlerts = alerts?.alerts || [];
  const totalAll = alerts?.total || allAlerts.length;

  const severityCounts = {};
  allAlerts.forEach((a) => {
    severityCounts[a.severity] = (severityCounts[a.severity] || 0) + 1;
  });

  const filtered = severityFilter === 'All'
    ? allAlerts
    : allAlerts.filter((a) => a.severity === severityFilter);

  const totalPages = Math.max(1, Math.ceil(filtered.length / ITEMS_PER_PAGE));
  const safePage = Math.min(page, totalPages);
  const startIndex = (safePage - 1) * ITEMS_PER_PAGE;
  const pageItems = filtered.slice(startIndex, startIndex + ITEMS_PER_PAGE);

  async function handleAcknowledge(alertId) {
    setAcknowledging((cur) => new Set(cur).add(alertId));
    setAckError('');
    try {
      await api.acknowledgeAlert(alertId);
      setAcknowledgedIds((cur) => new Set(cur).add(alertId));
    } catch (err) {
      setAckError(err.message || 'Failed to acknowledge alert.');
    } finally {
      setAcknowledging((cur) => {
        const next = new Set(cur);
        next.delete(alertId);
        return next;
      });
    }
  }

  return (
    <section className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.35em] text-emerald-300">Operational safety</p>
          <h2 className="text-4xl font-black text-white">Active OT Alerts</h2>
          <p className="mt-1 text-sm text-slate-500">{totalAll} alert{totalAll !== 1 ? 's' : ''} recorded</p>
        </div>
        <div className="inline-flex items-center gap-2 rounded-3xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-sm text-slate-300">
          <ShieldAlert className="h-5 w-5 text-emerald-300" /> Latest scan intelligence
        </div>
      </div>

      {/* Severity filter tabs */}
      <div className="flex flex-wrap items-center gap-2">
        <Filter className="h-4 w-4 text-slate-500" />
        {severityOptions.map((sev) => (
          <button
            key={sev}
            type="button"
            onClick={() => { setSeverityFilter(sev); setPage(1); }}
            className={`rounded-full border px-4 py-1.5 text-xs font-semibold transition ${
              severityFilter === sev
                ? 'border-emerald-400/40 bg-emerald-400/15 text-emerald-200'
                : 'border-slate-700 bg-slate-800/50 text-slate-400 hover:border-slate-600 hover:text-slate-300'
            }`}
          >
            {sev === 'All' ? 'All' : (
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ background: severityColors[sev] }} />
                {sev}
              </span>
            )}
            {severityCounts[sev] > 0 && (
              <span className="ml-1.5 rounded-full bg-slate-800 px-1.5 py-0.5 text-xs">
                {sev === 'All' ? totalAll : severityCounts[sev]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Ack error */}
      {ackError && (
        <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">
          {ackError}
        </div>
      )}

      {/* Alerts list */}
      <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
        {pageItems.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-3xl border border-slate-800 bg-slate-950/80 p-10 text-slate-400">
            {severityFilter !== 'All' ? (
              <>
                <ShieldCheck className="mb-3 h-12 w-12 text-emerald-400" />
                <p>No {severityFilter.toLowerCase()} alerts.</p>
              </>
            ) : (
              <>
                <ShieldCheck className="mb-3 h-12 w-12 text-emerald-400" />
                <p>No active alerts currently.</p>
              </>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            {pageItems.map((alert) => {
              const isAcknowledged = acknowledgedIds.has(alert.id);
              const isAcknowledging = acknowledging.has(alert.id);
              return (
                <article
                  key={alert.id}
                  className={`rounded-3xl border p-5 transition ${
                    isAcknowledged
                      ? 'border-slate-700 bg-slate-950/40 opacity-60'
                      : 'border-slate-800 bg-slate-950/80'
                  }`}
                >
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <p className="text-xs uppercase tracking-[0.25em] text-slate-500">
                          {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'Unknown'}
                        </p>
                        {isAcknowledged && (
                          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-600/30 bg-emerald-600/10 px-2 py-0.5 text-xs text-emerald-300">
                            <Check className="h-3 w-3" /> Acknowledged
                          </span>
                        )}
                      </div>
                      <h3 className="text-xl font-black text-white">{alert.title}</h3>
                    </div>
                    <div className="flex items-center gap-3">
                      {!isAcknowledged && (
                        <button
                          type="button"
                          onClick={() => handleAcknowledge(alert.id)}
                          disabled={isAcknowledging}
                          className="inline-flex items-center gap-1.5 rounded-xl border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-xs font-bold text-emerald-200 transition hover:bg-emerald-400 hover:text-slate-950 disabled:opacity-50"
                        >
                          {isAcknowledging ? 'Acknowledging...' : <><Check className="h-3.5 w-3.5" /> Acknowledge</>}
                        </button>
                      )}
                      <AlertBadge severity={alert.severity} />
                    </div>
                  </div>
                  <p className="mt-4 text-sm text-slate-400">{alert.message}</p>
                  {alert.asset_hostname && (
                    <p className="mt-3 flex items-center gap-2 text-sm text-slate-500">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      Affected asset: <span className="font-semibold text-slate-100">{alert.asset_hostname}</span>
                    </p>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/70 px-5 py-3">
          <span className="text-sm text-slate-400">
            Page {safePage} of {totalPages} ({filtered.length} alert{filtered.length !== 1 ? 's' : ''})
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
            <span className="text-sm text-slate-500 mx-1">{safePage}</span>
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
