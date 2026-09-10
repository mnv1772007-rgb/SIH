import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const RISK_STYLE = {
  critical: 'border-rose-500/40 bg-rose-500/10 text-rose-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
}

const STATUS_STYLE = {
  investigating: 'text-cyan-300',
  monitoring: 'text-amber-300',
  resolved: 'text-emerald-400',
}

export default function CasesDrawer({ open, cases, onClose, onCreateCase }) {
  return (
    <AnimatePresence>
      {open && (
        <>
          {/* backdrop */}
          <motion.div
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          {/* panel */}
          <motion.aside
            role="dialog"
            aria-label="Case management"
            className="glass fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col rounded-none border-l border-white/10 bg-cyber-panel/95"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] p-4">
              <div>
                <h2 className="font-mono text-sm font-bold tracking-widest text-cyan-300">
                  CASE MANAGEMENT
                </h2>
                <p className="mt-0.5 font-mono text-[10px] tracking-widest text-slate-500">
                  {cases.length} INVESTIGATIONS
                </p>
              </div>
              <button
                onClick={onClose}
                aria-label="Close cases"
                className="rounded-md border border-white/10 p-1.5 text-slate-400 transition hover:border-rose-500/40 hover:text-rose-300"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            <div className="border-b border-white/[0.06] p-4">
              <button
                onClick={onCreateCase}
                className="flex w-full items-center justify-center gap-2 rounded-xl border border-dashed border-cyan-400/40 bg-cyan-400/[0.06] px-4 py-3 font-mono text-[11px] font-bold tracking-widest text-cyan-300 transition hover:bg-cyan-400/[0.12] hover:shadow-[0_0_20px_rgba(34,211,238,0.15)]"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <line x1="12" y1="5" x2="12" y2="19" />
                  <line x1="5" y1="12" x2="19" y2="12" />
                </svg>
                CREATE CASE FROM CURRENT ANALYSIS
              </button>
            </div>

            <div className="flex-1 space-y-2 overflow-y-auto p-4">
              <AnimatePresence initial={false}>
                {cases.map((c) => (
                  <motion.div
                    key={c.id}
                    layout
                    initial={{ opacity: 0, y: -12 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-3"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-sm font-medium text-slate-200">{c.title}</span>
                      <span
                        className={`shrink-0 rounded border px-1.5 py-px font-mono text-[10px] font-bold uppercase ${RISK_STYLE[c.risk_level] ?? RISK_STYLE.low}`}
                      >
                        {c.risk_level} {typeof c.risk_score === 'number' ? c.risk_score.toFixed(0) : ''}
                      </span>
                    </div>
                    <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-slate-500">
                      <span className={STATUS_STYLE[c.status] ?? 'text-slate-400'}>
                        ● {c.status?.toUpperCase()}
                      </span>
                      <span>{c.email_count} EMAILS</span>
                      <span>{new Date(c.created_at).toLocaleDateString()}</span>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              {cases.length === 0 && (
                <p className="pt-8 text-center font-mono text-xs text-slate-600">NO OPEN CASES</p>
              )}
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  )
}
