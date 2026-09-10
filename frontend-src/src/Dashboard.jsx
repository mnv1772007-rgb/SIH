import React, { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Globe3D from './components/Globe3D.jsx'
import ThreatAssessment from './components/ThreatAssessment.jsx'
import HeaderForensics from './components/HeaderForensics.jsx'
import LiveAlertFeed from './components/LiveAlertFeed.jsx'
import UploadZone from './components/UploadZone.jsx'
import CasesDrawer from './components/CasesDrawer.jsx'
import RiskDistribution from './components/RiskDistribution.jsx'
import { threatData, initialAlerts, generateAlert } from './data/mockData.js'
import { checkHealth, getCases, createCase } from './services/api.js'

/**
 * SENTINEL — AI Email Threat Detection & Forensic Intelligence Dashboard
 *
 * State contract: every panel consumes the FastAPI-shaped analysis object
 * { message_id, sender_domain, origin_ip, spf_status, dkim_status, dmarc_status,
 *   extracted_urls, email_body_text, ip_geolocation, domain_age_days,
 *   threat_intel_flags, ai_nlp_intent, ai_risk_score }
 *
 * Swap the mock `threatData` for a fetch() against the FastAPI backend when ready.
 */
export default function Dashboard() {
  // Currently displayed forensic analysis
  const [current, setCurrent] = useState(threatData)
  // Live feed of incoming suspicious emails
  const [alerts, setAlerts] = useState(initialAlerts)
  // New-analysis upload modal
  const [showUpload, setShowUpload] = useState(false)
  // Case management drawer
  const [showCases, setShowCases] = useState(false)
  const [cases, setCases] = useState([])
  // null = probing, true = FastAPI reachable, false = mock mode
  const [backendOnline, setBackendOnline] = useState(null)
  const idRef = useRef(100000)

  // Load investigation cases (API or mock)
  useEffect(() => {
    getCases().then(setCases).catch(() => {})
  }, [])

  // ESC closes any overlay
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        setShowUpload(false)
        setShowCases(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const handleCreateCase = async () => {
    try {
      const created = await createCase(current)
      setCases((prev) => [created, ...prev])
    } catch (err) {
      console.error('[dashboard] failed to create case:', err)
    }
  }

  // Simulate realtime alert stream until the FastAPI websocket is connected
  useEffect(() => {
    const timer = setInterval(() => {
      setAlerts((prev) => [generateAlert(++idRef.current), ...prev].slice(0, 12))
    }, 6000)
    return () => clearInterval(timer)
  }, [])

  // Probe the FastAPI backend at mount, then re-check every 30s
  useEffect(() => {
    let alive = true
    const ping = async () => {
      const ok = await checkHealth()
      if (alive) setBackendOnline(ok)
    }
    ping()
    const timer = setInterval(ping, 30000)
    return () => {
      alive = false
      clearInterval(timer)
    }
  }, [])

  // UploadZone finished -> load result into every panel + push into feed
  const handleAnalysisComplete = (result, source) => {
    setCurrent(result)
    setAlerts((prev) => [result, ...prev].slice(0, 12))
    setShowUpload(false)
    console.info(`[dashboard] analysis loaded via ${source}:`, result.analysis_id)
  }

  return (
    <div className="grid-bg flex min-h-screen flex-col">
      {/* ===== Top bar ===== */}
      <header className="sticky top-0 z-20 border-b border-white/[0.06] bg-cyber-bg/70 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4 px-4 py-3 lg:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 text-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.25)]">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </div>
            <div>
              <h1 className="font-mono text-sm font-bold tracking-widest text-slate-100">
                SENTINEL<span className="text-cyan-400">//SOC</span>
              </h1>
              <p className="font-mono text-[9px] tracking-[0.2em] text-slate-500">
                AI EMAIL THREAT FORENSICS
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div
              className={`hidden items-center gap-2 rounded-full border px-3 py-1 md:flex ${
                backendOnline == null
                  ? 'border-slate-500/20 bg-slate-500/5'
                  : backendOnline
                    ? 'border-emerald-500/20 bg-emerald-500/5'
                    : 'border-amber-500/20 bg-amber-500/5'
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  backendOnline == null
                    ? 'bg-slate-400 animate-pulse'
                    : backendOnline
                      ? 'bg-emerald-400'
                      : 'bg-amber-400 pulse-warning'
                }`}
              />
              <span
                className={`font-mono text-[10px] ${
                  backendOnline == null
                    ? 'text-slate-400'
                    : backendOnline
                      ? 'text-emerald-300'
                      : 'text-amber-300'
                }`}
              >
                {backendOnline == null ? 'API: PROBING…' : backendOnline ? 'API: ONLINE' : 'API: OFFLINE · MOCK'}
              </span>
            </div>
            <div className="hidden items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 xl:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 pulse-warning" />
              <span className="font-mono text-[10px] text-slate-400">
                NODE: {current.ip_geolocation.asn}
              </span>
            </div>
            <button
              onClick={() => setShowCases(true)}
              className="hidden items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 font-mono text-[11px] font-bold tracking-wide text-slate-300 transition hover:border-purple-400/40 hover:text-purple-300 sm:flex"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
              </svg>
              CASES
              <span className="rounded bg-white/10 px-1 text-[9px]">{cases.length}</span>
            </button>
            <button
              onClick={() => setShowUpload(true)}
              className="flex items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3 py-1.5 font-mono text-[11px] font-bold tracking-wide text-cyan-300 transition hover:bg-cyan-400/20 hover:shadow-[0_0_20px_rgba(34,211,238,0.25)]"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
              NEW ANALYSIS
            </button>
          </div>
        </div>
      </header>

      {/* ===== Main grid ===== */}
      <main className="mx-auto grid w-full max-w-[1600px] flex-1 grid-cols-1 gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_360px] lg:px-6">
        {/* Left column */}
        <div className="flex min-w-0 flex-col gap-4">
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
            <HeaderForensics data={current} />
          </motion.div>

          <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
            {/* 3D globe */}
            <motion.div
              className="glass relative min-h-[380px] overflow-hidden"
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.6, delay: 0.1 }}
            >
              <Globe3D data={current} />
            </motion.div>

            {/* Risk assessment */}
            <motion.div
              className="min-h-[380px]"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <ThreatAssessment data={current} />
            </motion.div>
          </div>

          {/* Intent distribution graph (live alert stream) */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
            <RiskDistribution alerts={alerts} />
          </motion.div>
        </div>

        {/* Right sidebar — live feed */}
        <motion.div
          className="min-h-[420px] lg:sticky lg:top-[73px] lg:h-[calc(100vh-73px-2rem)]"
          initial={{ opacity: 0, x: 24 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.15 }}
        >
          <LiveAlertFeed
            alerts={alerts}
            selectedId={current.message_id}
            onSelect={setCurrent}
          />
        </motion.div>
      </main>

      {/* ===== Footer status bar ===== */}
      <footer className="border-t border-white/[0.06] bg-cyber-bg/80 px-4 py-2 lg:px-6">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between font-mono text-[9px] tracking-widest text-slate-600">
          <span>SENTINEL v2.4 · CONTRACT-FIRST · FASTAPI READY</span>
          <span className="hidden sm:block">
            ANALYZING: <span className="text-cyan-400/80">{current.message_id}</span>
          </span>
        </div>
      </footer>

      {/* ===== New Analysis modal (drag & drop upload) ===== */}
      <AnimatePresence>
        {showUpload && (
          <motion.div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowUpload(false)}
          >
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-label="New email analysis"
              className="glass w-full max-w-lg p-6"
              initial={{ opacity: 0, scale: 0.92, y: 24 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.92, y: 24 }}
              transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="font-mono text-sm font-bold tracking-widest text-cyan-300">
                    NEW FORENSIC ANALYSIS
                  </h2>
                  <p className="mt-0.5 font-mono text-[10px] tracking-widest text-slate-500">
                    UPLOAD SUSPICIOUS EMAIL · {backendOnline ? 'LIVE API' : 'MOCK PIPELINE'}
                  </p>
                </div>
                <button
                  onClick={() => setShowUpload(false)}
                  aria-label="Close"
                  className="rounded-md border border-white/10 p-1.5 text-slate-400 transition hover:border-rose-500/40 hover:text-rose-300"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </div>

              <UploadZone onComplete={handleAnalysisComplete} />
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ===== Case management drawer ===== */}
      <CasesDrawer
        open={showCases}
        cases={cases}
        onClose={() => setShowCases(false)}
        onCreateCase={handleCreateCase}
      />
    </div>
  )
}
