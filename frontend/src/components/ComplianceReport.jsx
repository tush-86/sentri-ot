import React, { useState } from 'react';
import {
  Check, ChevronDown, ChevronRight, Download, FileCheck2,
  ShieldCheck, ShieldQuestion, ShieldX, AlertTriangle, Target, ThumbsUp
} from 'lucide-react';
import { api } from '../lib/api';

const statusStyles = {
  PASS: { icon: ShieldCheck, className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' },
  PARTIAL: { icon: ShieldQuestion, className: 'border-amber-500/30 bg-amber-500/10 text-amber-300' },
  FAIL: { icon: ShieldX, className: 'border-red-500/30 bg-red-500/10 text-red-300' },
  'NOT OBSERVABLE': { icon: ShieldQuestion, className: 'border-slate-600/30 bg-slate-800 text-slate-400' },
};

function StatusPill({ status }) {
  const style = statusStyles[status] || statusStyles.PARTIAL;
  const Icon = style.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-black ${style.className}`}>
      <Icon className="h-3.5 w-3.5" />{status}
    </span>
  );
}

const severityBadgeStyles = {
  Critical: 'border-red-500/30 bg-red-500/15 text-red-300',
  High: 'border-orange-500/30 bg-orange-500/15 text-orange-300',
  Medium: 'border-amber-500/30 bg-amber-500/15 text-amber-300',
  Low: 'border-emerald-500/30 bg-emerald-500/15 text-emerald-300',
};

const frameworks = [
  { id: 'DESC', label: 'DESC ICS/OT alignment' },
  { id: 'IEC 62443', label: 'IEC 62443-3-3 base SR' },
];

function ScoreGauge({ score }) {
  const color = score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-red-400';
  const ringColor = score >= 80 ? 'stroke-emerald-400' : score >= 60 ? 'stroke-amber-400' : 'stroke-red-400';
  const circumference = 2 * Math.PI * 60;
  const offset = circumference - (circumference * (score / 100));

  return (
    <div className="relative flex items-center justify-center">
      <svg width="160" height="160" className="-rotate-90">
        <circle cx="80" cy="80" r="60" fill="none" stroke="#1e293b" strokeWidth="14" />
        <circle cx="80" cy="80" r="60" fill="none" className={ringColor} strokeWidth="14"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-4xl font-black ${color}`}>{score}</span>
        <span className="text-xs text-slate-400">/ 100</span>
      </div>
    </div>
  );
}

function RatingBadge({ rating }) {
  const colorMap = {
    'A': 'border-emerald-400/50 bg-emerald-400/20 text-emerald-300',
    'B': 'border-emerald-400/40 bg-emerald-400/15 text-emerald-200',
    'C': 'border-amber-400/40 bg-amber-400/15 text-amber-200',
    'D': 'border-orange-400/40 bg-orange-400/15 text-orange-200',
    'F': 'border-red-400/40 bg-red-400/15 text-red-200',
  };
  return (
    <span className={`text-3xl font-black rounded-full border px-4 py-1 ${colorMap[rating] || 'border-slate-700 bg-slate-800 text-slate-300'}`}>
      {rating || '--'}
    </span>
  );
}

function CategoryCard({ category, isExpanded, onToggle, domainName }) {
  const score = category.score ?? 0;
  const color = score >= 80 ? 'bg-emerald-400' : score >= 60 ? 'bg-amber-400' : 'bg-red-400';

  const passCount = (category.controls || []).filter(c => c.status === 'PASS').length;
  const failCount = (category.controls || []).filter(c => c.status === 'FAIL').length;
  const partialCount = (category.controls || []).filter(c => c.status === 'PARTIAL').length;
  const totalControls = (category.controls || []).length;

  return (
    <div className="rounded-3xl border border-slate-800 bg-slate-900/70">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between p-5 text-left transition hover:bg-slate-800/30"
      >
        <div className="flex-1">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h4 className="font-bold text-white">{category.name}</h4>
              {domainName && <p className="text-xs text-slate-500">{domainName}</p>}
            </div>
            <span className="text-lg font-black text-white">{score}<span className="text-sm text-slate-500">%</span></span>
          </div>
          <div className="mb-3 h-2.5 rounded-full bg-slate-800">
            <div className={`h-2.5 rounded-full ${color} transition-all`} style={{ width: `${Math.max(2, score)}%` }} />
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            {totalControls > 0 && (
              <>
                {passCount > 0 && <span className="text-emerald-400">{passCount} pass{passCount > 1 ? 'es' : ''}</span>}
                {failCount > 0 && <span className="text-red-400">{failCount} fail{`${failCount > 1 ? 's' : ''}`}</span>}
                {partialCount > 0 && <span className="text-amber-400">{partialCount} partial</span>}
                <span className="text-slate-500">{totalControls} total</span>
              </>
            )}
          </div>
        </div>
        {isExpanded ? <ChevronDown className="ml-4 h-5 w-5 shrink-0 text-slate-400" /> : <ChevronRight className="ml-4 h-5 w-5 shrink-0 text-slate-400" />}
      </button>
      {isExpanded && (
        <div className="border-t border-slate-800 px-5 pb-5 pt-4 space-y-3">
          {totalControls === 0 ? (
            <p className="text-sm text-slate-500">No controls data available for this category.</p>
          ) : (
            category.controls.map((control) => (
              <SingleControl key={control.id} control={control} />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function SingleControl({ control }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/60">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between p-4 text-left transition hover:bg-slate-800/20"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span className="shrink-0 font-mono text-xs text-cyan-400">{control.id}</span>
          <span className="text-sm text-slate-200 truncate">{control.title || control.requirement}</span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <StatusPill status={control.status} />
          {expanded ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
        </div>
      </button>
      {expanded && (
        <div className="border-t border-slate-800 px-4 pb-4 pt-3 space-y-3">
          {control.description && (
            <p className="text-sm text-slate-400">{control.description}</p>
          )}
          {control.requirement && !control.title && (
            <p className="text-sm text-slate-400">{control.requirement}</p>
          )}
          {control.evidence?.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-emerald-400">Evidence Found</p>
              <ul className="space-y-1">
                {control.evidence.map((ev, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                    {ev}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {control.gaps?.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-red-400">Gaps</p>
              <ul className="space-y-1">
                {control.gaps.map((gap, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <ShieldX className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                    {gap}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {control.recommendation && (
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3">
              <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-emerald-400">Recommendation</p>
              <p className="text-sm text-slate-300">{control.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ComplianceReport({ compliance, loading, error }) {
  const [activeFramework, setActiveFramework] = useState('DESC');
  const [expandedCategories, setExpandedCategories] = useState({});

  if (loading) return <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-10 text-slate-400">Loading compliance evidence...</div>;
  if (error) return <div className="rounded-3xl border border-red-900/60 bg-red-950/30 p-10 text-red-200">{error}</div>;

  const frameworksData = compliance?.frameworks || {};
  const frameworkData = frameworksData[activeFramework] || { categories: [], score: 0, rating: '', last_evaluated: null };
  const categories = frameworkData.categories || [];
  const overallScore = frameworkData.score ?? 0;

  function toggleCategory(name) {
    setExpandedCategories((cur) => ({ ...cur, [name]: !cur[name] }));
  }

  // Gather all controls for critical findings and strengths
  const allControls = categories.flatMap(cat => (cat.controls || []));
  const failControls = allControls.filter(c => c.status === 'FAIL').sort((a, b) => {
    const order = { Critical: 4, High: 3, Medium: 2, Low: 1, Unknown: 0 };
    return (order[b.severity || 'Unknown'] || 0) - (order[a.severity || 'Unknown'] || 0);
  });
  const passControls = allControls.filter(c => c.status === 'PASS');

  return (
    <section className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.35em] text-emerald-300">Regulatory posture</p>
          <h2 className="text-4xl font-black text-white">Compliance Report</h2>
        </div>
        <button
          type="button"
          onClick={api.downloadReport}
          className="inline-flex items-center justify-center gap-2 rounded-2xl border border-emerald-400/40 bg-emerald-400/10 px-5 py-3 font-bold text-emerald-200 transition hover:bg-emerald-400 hover:text-slate-950"
        >
          <Download className="h-4 w-4" /> Download PDF
        </button>
      </div>

      {/* Framework Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-0.5">
        {frameworks.map((fw) => (
          <button
            key={fw.id}
            type="button"
            onClick={() => setActiveFramework(fw.id)}
            className={`rounded-t-xl px-5 py-3 text-sm font-bold transition ${
              activeFramework === fw.id
                ? 'border border-b-0 border-slate-800 bg-slate-900/80 text-white'
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/40'
            }`}
          >
            {fw.label}
          </button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-[0.6fr_1.4fr]">
        {/* Score Card */}
        <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="flex items-center justify-between mb-4">
            <FileCheck2 className="h-8 w-8 text-emerald-300" />
            <RatingBadge rating={frameworkData.rating || compliance?.rating || ''} />
          </div>
          <ScoreGauge score={overallScore} />
          <p className="mt-4 text-center text-sm text-slate-400">
            DESC ICS/OT alignment &bull; IEC 62443-3-3 base SR
          </p>
          {frameworkData.last_evaluated && (
            <p className="mt-2 text-center text-xs text-slate-500">
              Evaluated: {new Date(frameworkData.last_evaluated).toLocaleString()}
            </p>
          )}
          {!frameworkData.last_evaluated && compliance?.last_evaluated && (
            <p className="mt-2 text-center text-xs text-slate-500">
              Evaluated: {new Date(compliance.last_evaluated).toLocaleString()}
            </p>
          )}
          <div className="mt-5 flex justify-center gap-3 text-xs text-slate-500">
            <span className="flex items-center gap-1"><ShieldCheck className="h-3 w-3 text-emerald-400" /> {allControls.filter(c => c.status === 'PASS').length} Pass</span>
            <span className="flex items-center gap-1"><ShieldX className="h-3 w-3 text-red-400" /> {allControls.filter(c => c.status === 'FAIL').length} Fail</span>
            <span className="flex items-center gap-1"><ShieldQuestion className="h-3 w-3 text-amber-400" /> {allControls.filter(c => c.status === 'PARTIAL').length} Partial</span>
          </div>
        </div>

        {/* Category Breakdown */}
        <div className="space-y-4">
          <h3 className="text-lg font-bold text-white">Category Breakdown</h3>
          {categories.length === 0 ? (
            <div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-8 text-center text-slate-500">
              No compliance data available for {activeFramework}. Run a scan to generate controls evidence.
            </div>
          ) : (
            categories.map((cat) => (
              <CategoryCard
                key={cat.name}
                category={cat}
                isExpanded={expandedCategories[cat.name]}
                onToggle={() => toggleCategory(cat.name)}
                domainName={cat.domain}
              />
            ))
          )}
        </div>
      </div>

      {/* Critical Findings */}
      {failControls.length > 0 && (
        <div className="rounded-3xl border border-red-800/50 bg-red-950/20 p-6">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-white">
            <AlertTriangle className="h-5 w-5 text-red-400" /> Critical Findings
          </h3>
          <p className="mb-4 text-sm text-slate-400">Top {Math.min(5, failControls.length)} gap{failControls.length > 1 ? 's' : ''} requiring immediate attention</p>
          <div className="grid gap-3 md:grid-cols-2">
            {failControls.slice(0, 5).map((control) => (
              <div key={control.id} className="rounded-2xl border border-red-800/40 bg-slate-900/90 p-4">
                <div className="mb-2 flex items-center justify-between">
                  <span className="font-mono text-xs text-red-300">{control.id}</span>
                  {control.severity && <span className={`rounded-full px-2 py-0.5 text-xs font-bold ${severityBadgeStyles[control.severity] || 'border-slate-700 bg-slate-800 text-slate-300'}`}>{control.severity}</span>}
                </div>
                <p className="text-sm font-semibold text-white">{control.title || control.requirement}</p>
                {control.gaps?.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {control.gaps.slice(0, 3).map((gap, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-400">
                        <ShieldX className="mt-0.5 h-3 w-3 shrink-0 text-red-400" />
                        {gap}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Strengths */}
      {passControls.length > 0 && (
        <div className="rounded-3xl border border-emerald-800/40 bg-emerald-950/10 p-6">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-white">
            <ThumbsUp className="h-5 w-5 text-emerald-400" /> Strengths
          </h3>
          <p className="mb-4 text-sm text-slate-400">Top areas of compliance achievement</p>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {passControls.slice(0, 6).map((control) => (
              <div key={control.id} className="rounded-2xl border border-emerald-800/30 bg-slate-900/80 p-4">
                <div className="mb-1 flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  <span className="font-mono text-xs text-emerald-300">{control.id}</span>
                </div>
                <p className="text-sm text-slate-200">{control.title || control.requirement}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
