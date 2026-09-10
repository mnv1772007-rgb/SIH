import React from 'react'
import { motion } from 'framer-motion'
import { exportReportJson } from '../services/api.js'

const scoreColor = (score) =>
  score >= 75 ? '#f43f5e' : score >= 45 ? '#f59e0b' : '#10b981'

const verdict = (score) =>
  score >= 75 ? { label: 'CRITICAL THREAT', cls: 'text-rose-400 border-rose-500/40 bg-rose-500/10' }
  : score >= 45 ? { label: 'SUSPICIOUS', cls: 'text-amber-300 border-amber-500/40 bg-amber-500/10' }
  : { label: 'BENIGN', cls: 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' }

/** Animated radial gauge for ai_risk_score. */
function RiskGauge({ score }) {
  const R = 64
  const CIRC = 2 * Math.PI * R
  const arc = CIRC * 0.75 // 270° sweep
  const filled = (score / 100) * arc
  const color = scoreColor(score)

  return (
    <div className="relative mx-auto h-44 w-44">
      <svg viewBox="0 0 160 160" className="h-full w-full -rotate-[135deg]">
        {/* track */}
        <circle
          cx="80" cy="80" r={R} fill="none"
          stroke="rgba(148,163,184,0.12)" strokeWidth="10"
          strokeLinecap="round" strokeDasharray={`${arc} ${CIRC}`}
        />
        {/* value arc */}
        <motion.circle
          cx="80" cy="80" r={R} fill="none"
          stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${arc} ${CIRC}`}
          initial={{ strokeDashoffset: arc }}
          animate={{ strokeDashoffset: arc - filled }}
          transition={{ duration: 1.6, ease: [0.16, 1, 0.3, 1] }}
          style={{ filter: `drop-shadow(0 0 8px ${color})` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          className="font-mono text-4xl font-bold"
          style={{ color }}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          {score.toFixed(1)}
        </motion.span>
        <span className="font-mono text-[10px] tracking-widest text-slate-500">AI RISK SCORE</span>
      </div>
    </div>
  )
}

export default function ThreatAssessment({ data }) {
  const v = verdict(data.ai_risk_score)
  const isHigh = data.ai_risk_score >= 75

  return (
    <div className="glass flex h-full flex-col p-5">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="font-mono text-xs font-semibold tracking-widest text-cyan-300">
          THREAT ASSESSMENT
        </h2>
        <span className={`rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold ${v.cls} ${isHigh ? 'pulse-warning' : ''}`}>
          {v.label}
        </span>
      </div>

      <RiskGauge score={data.ai_risk_score} />

      {/* AI NLP intent */}
      <div className="mt-3 rounded-lg border border-purple-500/20 bg-purple-500/5 px-3 py-2">
        <div className="font-mono text-[10px] tracking-widest text-purple-300/70">AI NLP INTENT</div>
        <div className="mt-0.5 text-sm font-semibold text-purple-200">{data.ai_nlp_intent}</div>
      </div>

      {/* domain age */}
      <div className="mt-2 flex items-center justify-between rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2">
        <span className="font-mono text-[10px] tracking-widest text-slate-400">DOMAIN AGE</span>
        <span className={`font-mono text-sm font-bold ${data.domain_age_days < 30 ? 'text-rose-400' : 'text-slate-200'}`}>
          {data.domain_age_days}d
          {data.domain_age_days < 30 && <span className="ml-1 text-[9px] text-rose-400/70">NEWLY REGISTERED</span>}
        </span>
      </div>

      {/* threat intel flags */}
      <div className="mt-3 flex-1">
        <div className="mb-2 font-mono text-[10px] tracking-widest text-slate-400">THREAT INTEL FLAGS</div>
        <ul className="space-y-2">
          {data.threat_intel_flags.map((flag) => (
            <li
              key={flag}
              className={`flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 ${isHigh ? 'animate-glow-red' : ''}`}
            >
              <span className={`h-1.5 w-1.5 rounded-full bg-rose-500 ${isHigh ? 'pulse-warning' : ''}`} />
              <span className="font-mono text-xs text-rose-200">{flag}</span>
            </li>
          ))}
          {data.threat_intel_flags.length === 0 && (
            <li className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-1.5 font-mono text-xs text-emerald-300">
              NO INTEL HITS
            </li>
          )}
        </ul>
      </div>

      {/* ASN footer */}
      <div className="mt-3 border-t border-white/5 pt-2 font-mono text-[10px] text-slate-500">
        {data.ip_geolocation.asn} · {data.ip_geolocation.country}
      </div>

      {/* export */}
      <button
        onClick={() => exportReportJson(data)}
        className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 font-mono text-[10px] font-bold tracking-widest text-slate-300 transition hover:border-cyan-400/40 hover:text-cyan-300"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
        EXPORT FORENSIC REPORT (.JSON)
      </button>
    </div>
  )
}
