import React, { useState } from 'react'

function StatusBadge({ status }) {
  const ok = status === 'pass'
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-bold uppercase ${
        ok
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
          : 'border-rose-500/40 bg-rose-500/10 text-rose-400'
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-emerald-400' : 'bg-rose-500 pulse-warning'}`} />
      {status}
    </span>
  )
}

function Cell({ label, mono, copyValue, children }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    if (!copyValue) return
    try {
      await navigator.clipboard.writeText(copyValue)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div
      role={copyValue ? 'button' : undefined}
      title={copyValue ? 'Click to copy' : undefined}
      onClick={copy}
      className={`min-w-0 rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2.5 transition ${
        copyValue ? 'cursor-pointer hover:border-cyan-400/30' : ''
      }`}
    >
      <div className="flex items-center justify-between gap-1">
        <span className="font-mono text-[9px] tracking-widest text-slate-500">{label}</span>
        {copyValue && (
          <span className={`font-mono text-[8px] ${copied ? 'text-emerald-400' : 'text-slate-600'}`}>
            {copied ? 'COPIED ✓' : '⧉'}
          </span>
        )}
      </div>
      <div className={`mt-1 truncate text-sm ${mono ? 'font-mono' : 'font-medium'} text-slate-200`}>
        {children}
      </div>
    </div>
  )
}

export default function HeaderForensics({ data }) {
  return (
    <div className="glass p-5">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-mono text-xs font-semibold tracking-widest text-cyan-300">
          HEADER FORENSICS
        </h2>
        <span className="font-mono text-[10px] text-slate-500">
          AUTH PROTOCOL VALIDATION
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 md:grid-cols-6">
        <Cell label="MESSAGE ID" mono copyValue={data.message_id}>
          {data.message_id}
        </Cell>
        <Cell label="SENDER DOMAIN" mono copyValue={data.sender_domain}>
          <span className={data.spf_status === 'fail' && data.dmarc_status === 'fail' ? 'text-rose-300' : ''}>
            {data.sender_domain}
          </span>
        </Cell>
        <Cell label="ORIGIN IP" mono copyValue={data.origin_ip}>
          <span className="text-rose-300">{data.origin_ip}</span>
        </Cell>
        <Cell label="SPF">
          <StatusBadge status={data.spf_status} />
        </Cell>
        <Cell label="DKIM">
          <StatusBadge status={data.dkim_status} />
        </Cell>
        <Cell label="DMARC">
          <StatusBadge status={data.dmarc_status} />
        </Cell>
      </div>
    </div>
  )
}
