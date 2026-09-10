import React, { useCallback, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { analyzeEmail } from '../services/api.js'

const ACCEPTED = ['.eml', '.msg', '.txt']

const STAGES = [
  { at: 0, label: 'PARSING MIME HEADERS' },
  { at: 25, label: 'RESOLVING ORIGIN IP / GEO' },
  { at: 50, label: 'QUERYING THREAT INTEL FEEDS' },
  { at: 72, label: 'RUNNING AI NLP INTENT MODEL' },
  { at: 92, label: 'COMPILING FORENSIC REPORT' },
]

const isAccepted = (file) =>
  ACCEPTED.some((ext) => file.name.toLowerCase().endsWith(ext))

export default function UploadZone({ onComplete }) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState(null)
  const [progress, setProgress] = useState(null) // null = idle
  const [error, setError] = useState(null)
  const inputRef = useRef(null)

  const stageLabel =
    progress == null ? '' : [...STAGES].reverse().find((s) => progress >= s.at)?.label ?? 'UPLOADING'

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    const dropped = e.dataTransfer.files?.[0]
    if (!dropped) return
    if (!isAccepted(dropped)) {
      setError(`Unsupported file type — drop a ${ACCEPTED.join(' / ')} file`)
      return
    }
    setError(null)
    setFile(dropped)
  }, [])

  const runAnalysis = async () => {
    if (!file || progress != null) return
    setError(null)
    setProgress(1)
    try {
      const { result, source } = await analyzeEmail(file, setProgress)
      onComplete(result, source)
    } catch (err) {
      setError(err.message || 'Analysis failed')
      setProgress(null)
    }
  }

  const reset = () => {
    setFile(null)
    setProgress(null)
    setError(null)
  }

  return (
    <div className="flex flex-col gap-4">
      {/* drop target */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Drop email file for analysis"
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => progress == null && inputRef.current?.click()}
        onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
        className={`relative flex min-h-[180px] cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-6 transition-colors ${
          dragging
            ? 'border-cyan-400/70 bg-cyan-400/[0.08] shadow-[0_0_30px_rgba(34,211,238,0.15)]'
            : 'border-white/15 bg-white/[0.02] hover:border-cyan-400/40'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPTED.join(',')}
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) { isAccepted(f) ? (setFile(f), setError(null)) : setError(`Unsupported file type — use ${ACCEPTED.join(' / ')}`) }
            e.target.value = ''
          }}
        />

        {file == null ? (
          <>
            <svg className={`h-10 w-10 ${dragging ? 'text-cyan-300' : 'text-slate-500'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M4 4h16v16H4z" opacity="0" />
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
            <p className="text-sm text-slate-300">
              Drag &amp; drop a suspicious <span className="font-mono text-cyan-300">.eml</span> / <span className="font-mono text-cyan-300">.msg</span> file
            </p>
            <p className="font-mono text-[10px] tracking-widest text-slate-500">OR CLICK TO BROWSE</p>
          </>
        ) : (
          <div className="flex w-full items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-cyan-400/30 bg-cyan-400/10">
              <svg className="h-5 w-5 text-cyan-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                <polyline points="22,6 12,13 2,6" />
              </svg>
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate font-mono text-sm text-slate-200">{file.name}</p>
              <p className="font-mono text-[10px] text-slate-500">{(file.size / 1024).toFixed(1)} KB</p>
            </div>
            {progress == null && (
              <button
                onClick={(e) => { e.stopPropagation(); reset() }}
                className="rounded-md border border-white/10 px-2 py-1 font-mono text-[10px] text-slate-400 hover:border-rose-500/40 hover:text-rose-300"
              >
                REMOVE
              </button>
            )}
          </div>
        )}
      </div>

      {/* progress */}
      <AnimatePresence>
        {progress != null && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="flex items-center justify-between font-mono text-[10px] tracking-widest">
              <span className="flex items-center gap-2 text-cyan-300">
                <span className="h-1.5 w-1.5 animate-ping rounded-full bg-cyan-400" />
                {stageLabel}
              </span>
              <span className="text-slate-400">{progress}%</span>
            </div>
            <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
              <motion.div
                className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-cyan-300 to-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.6)]"
                animate={{ width: `${progress}%` }}
                transition={{ ease: 'easeOut', duration: 0.35 }}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* error */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 font-mono text-[11px] text-rose-300">
          <span className="h-1.5 w-1.5 rounded-full bg-rose-500 pulse-warning" />
          {error}
        </div>
      )}

      {/* action */}
      <button
        onClick={runAnalysis}
        disabled={!file || progress != null}
        className="group relative w-full overflow-hidden rounded-xl border border-cyan-400/40 bg-cyan-400/10 px-4 py-3 font-mono text-xs font-bold tracking-widest text-cyan-300 transition enabled:hover:bg-cyan-400/20 enabled:hover:shadow-[0_0_25px_rgba(34,211,238,0.25)] disabled:cursor-not-allowed disabled:opacity-40"
      >
        {progress != null ? 'ANALYZING…' : '▶ RUN FULL FORENSIC ANALYSIS'}
      </button>
    </div>
  )
}
