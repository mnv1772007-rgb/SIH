import React, { useMemo } from 'react'
import { motion } from 'framer-motion'

/** Deterministic hue per intent so colors stay stable across refreshes. */
const INTENT_COLORS = {
  'Credential Harvesting': '#22d3ee',
  'Financial Fraud': '#f59e0b',
  'Malware Delivery': '#f43f5e',
  'Business Email Compromise': '#a855f7',
  'Spear Phishing': '#e879f9',
}
const FALLBACK_COLORS = ['#34d399', '#60a5fa', '#f472b6', '#fbbf24']
const colorFor = (intent, idx) => INTENT_COLORS[intent] ?? FALLBACK_COLORS[idx % FALLBACK_COLORS.length]

/**
 * Risk distribution chart — donut breakdown of the live alert feed by ai_nlp_intent,
 * with per-intent counts and average AI risk score. Recomputes whenever the
 * alert stream changes; no chart library, pure SVG to match the RiskGauge style.
 */
export default function RiskDistribution({ alerts }) {
  const segments = useMemo(() => {
    const groups = new Map()
    for (const a of alerts) {
      const g = groups.get(a.ai_nlp_intent) ?? { count: 0, riskSum: 0 }
      g.count += 1
      g.riskSum += a.ai_risk_score
      groups.set(a.ai_nlp_intent, g)
    }
    return [...groups.entries()]
      .map(([intent, g], idx) => ({
        intent,
        count: g.count,
        avgRisk: g.riskSum / g.count,
        color: colorFor(intent, idx),
      }))
      .sort((a, b) => b.count - a.count)
  }, [alerts])

  const total = segments.reduce((s, x) => s + x.count, 0)
  const maxCount = Math.max(1, ...segments.map((s) => s.count))

  // ---- donut geometry (270° sweep, same style as RiskGauge) ----
  const R = 58
  const CIRC = 2 * Math.PI * R
  const ARC = CIRC * 0.75
  const GAP = 4 // px gap between segments
  let cursor = 0
  const arcs = segments.map((s) => {
    const len = total ? Math.max((s.count / total) * ARC - GAP, 3) : 0
    const start = cursor
    cursor += (s.count / total) * ARC
    return { ...s, len, start }
  })

  return (
    <div className="glass flex h-full flex-col p-5">
      <div className="mb-1 flex items-center justify-between">
        <h2 className="font-mono text-xs font-semibold tracking-widest text-cyan-300">
          THREAT INTENT DISTRIBUTION
        </h2>
        <span className="rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-0.5 font-mono text-[10px] text-slate-400">
          {total} ALERTS
        </span>
      </div>

      {total === 0 ? (
        <div className="flex flex-1 items-center justify-center font-mono text-[11px] text-slate-500">
          NO DATA — AWAITING ALERT STREAM
        </div>
      ) : (
        <div className="mt-3 flex flex-1 flex-col items-center gap-5 sm:flex-row sm:gap-6">
          {/* Donut */}
          <div className="relative h-40 w-40 shrink-0">
            <svg viewBox="0 0 140 140" className="h-full w-full -rotate-[135deg]">
              <circle
                cx="70" cy="70" r={R} fill="none"
                stroke="rgba(148,163,184,0.10)" strokeWidth="12"
                strokeLinecap="round" strokeDasharray={`${ARC} ${CIRC}`}
              />
              {arcs.map((a) => (
                <motion.circle
                  key={a.intent}
                  cx="70" cy="70" r={R} fill="none"
                  stroke={a.color} strokeWidth="12" strokeLinecap="round"
                  strokeDasharray={`${a.len} ${CIRC}`}
                  initial={false}
                  animate={{ strokeDashoffset: -a.start }}
                  transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
                  style={{ filter: `drop-shadow(0 0 6px ${a.color}55)` }}
                />
              ))}
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <motion.span
                key={total}
                className="font-mono text-3xl font-bold text-slate-100"
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
              >
                {total}
              </motion.span>
              <span className="font-mono text-[9px] tracking-widest text-slate-500">
                FLAGGED EMAILS
              </span>
            </div>
          </div>

          {/* Legend with count bars */}
          <ul className="w-full flex-1 space-y-2">
            {arcs.map((s) => (
              <li key={s.intent}>
                <div className="flex items-center justify-between gap-2">
                  <span className="flex min-w-0 items-center gap-2">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ backgroundColor: s.color, boxShadow: `0 0 6px ${s.color}` }}
                    />
                    <span className="truncate text-xs text-slate-300">{s.intent}</span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    <span className="font-mono text-[10px] text-slate-500">
                      avg <span style={{ color: s.color }}>{s.avgRisk.toFixed(1)}</span>
                    </span>
                    <span className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-200">
                      {s.count}
                    </span>
                  </span>
                </div>
                <div className="ml-4 mt-1 h-1 overflow-hidden rounded-full bg-white/[0.04]">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ backgroundColor: s.color, opacity: 0.7 }}
                    initial={false}
                    animate={{ width: `${(s.count / maxCount) * 100}%` }}
                    transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
                  />
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
