import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const riskColor = (s) =>
  s >= 75 ? 'text-rose-400 border-rose-500/30' : s >= 45 ? 'text-amber-300 border-amber-500/30' : 'text-emerald-400 border-emerald-500/30'

function AlertCard({ alert, isSelected, onSelect }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <motion.article
      layout
      initial={{ opacity: 0, x: 40 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className={`overflow-hidden rounded-xl border backdrop-blur-md transition-colors ${
        isSelected
          ? 'border-cyan-400/40 bg-cyan-400/[0.06]'
          : 'border-white/[0.07] bg-white/[0.03] hover:border-white/[0.15]'
      }`}
    >
      <button
        className="flex w-full items-start gap-3 px-3 py-2.5 text-left"
        onClick={() => setExpanded((e) => !e)}
      >
        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full bg-rose-500 ${alert.ai_risk_score >= 75 ? 'pulse-warning' : 'opacity-60'}`} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <span className="truncate font-mono text-xs font-semibold text-slate-200">
              {alert.sender_domain}
            </span>
            <span className={`shrink-0 rounded border px-1.5 py-px font-mono text-[10px] font-bold ${riskColor(alert.ai_risk_score)}`}>
              {alert.ai_risk_score.toFixed(0)}
            </span>
          </div>
          <div className="mt-0.5 truncate font-mono text-[10px] text-slate-500">
            {alert.ai_nlp_intent} · {alert.ip_geolocation.country} · {alert.origin_ip}
          </div>
        </div>
        <svg
          className={`mt-1 h-3.5 w-3.5 shrink-0 text-slate-500 transition-transform ${expanded ? 'rotate-180' : ''}`}
          viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="space-y-2 border-t border-white/[0.06] px-3 py-2.5">
              <p className="text-[11px] leading-relaxed text-slate-400">{alert.email_body_text}</p>
              {alert.extracted_urls.map((url) => (
                <div
                  key={url}
                  className="flex items-center gap-1.5 rounded border border-rose-500/25 bg-rose-500/[0.07] px-2 py-1 font-mono text-[10px] text-rose-300 break-all"
                >
                  <svg className="h-3 w-3 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                  {url}
                </div>
              ))}
              <div className="flex items-center justify-between pt-1">
                <span className="font-mono text-[9px] text-slate-600">{alert.message_id}</span>
                <button
                  onClick={() => onSelect(alert)}
                  className="rounded border border-cyan-400/30 bg-cyan-400/10 px-2 py-1 font-mono text-[10px] font-semibold text-cyan-300 transition hover:bg-cyan-400/20"
                >
                  LOAD ANALYSIS →
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.article>
  )
}

export default function LiveAlertFeed({ alerts, selectedId, onSelect }) {
  return (
    <aside className="glass flex h-full min-h-0 flex-col p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="font-mono text-xs font-semibold tracking-widest text-cyan-300">
          LIVE ALERT FEED
        </h2>
        <span className="flex items-center gap-1.5 font-mono text-[10px] text-rose-400">
          <span className="h-1.5 w-1.5 rounded-full bg-rose-500 pulse-warning" />
          STREAMING
        </span>
      </div>

      <div className="grid grid-cols-3 gap-1.5 pb-3">
        <div className="rounded-lg border border-white/5 bg-white/[0.02] px-2 py-1.5 text-center">
          <div className="font-mono text-sm font-bold text-slate-200">{alerts.length}</div>
          <div className="font-mono text-[8px] tracking-widest text-slate-500">QUEUED</div>
        </div>
        <div className="rounded-lg border border-rose-500/20 bg-rose-500/5 px-2 py-1.5 text-center">
          <div className="font-mono text-sm font-bold text-rose-400">
            {alerts.filter((a) => a.ai_risk_score >= 75).length}
          </div>
          <div className="font-mono text-[8px] tracking-widest text-slate-500">CRITICAL</div>
        </div>
        <div className="rounded-lg border border-white/5 bg-white/[0.02] px-2 py-1.5 text-center">
          <div className="font-mono text-sm font-bold text-slate-200">
            {alerts.reduce((acc, a) => acc + a.threat_intel_flags.length, 0)}
          </div>
          <div className="font-mono text-[8px] tracking-widest text-slate-500">INTEL HITS</div>
        </div>
      </div>

      <div className="min-h-0 flex-1 space-y-2 overflow-y-auto pr-1">
        <AnimatePresence initial={false}>
          {alerts.map((alert) => (
            <AlertCard
              key={alert.message_id}
              alert={alert}
              isSelected={alert.message_id === selectedId}
              onSelect={onSelect}
            />
          ))}
        </AnimatePresence>
      </div>
    </aside>
  )
}
