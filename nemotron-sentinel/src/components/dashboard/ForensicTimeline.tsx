"use client";
import React, { useState } from "react";
import { motion } from "framer-motion";
import { Clock, ChevronDown, ChevronUp } from "lucide-react";
import { TimelineEvent } from "@/types/threat-intel";

interface ForensicTimelineProps {
  events: TimelineEvent[];
}

const SEV_CONFIG = {
  critical: { dot: "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]", text: "text-red-400", badge: "bg-red-500/15 border-red-500/30 text-red-300" },
  high:     { dot: "bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.7)]", text: "text-orange-400", badge: "bg-orange-500/15 border-orange-500/30 text-orange-300" },
  medium:   { dot: "bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.6)]", text: "text-yellow-400", badge: "bg-yellow-500/15 border-yellow-500/30 text-yellow-300" },
  low:      { dot: "bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]", text: "text-blue-400", badge: "bg-blue-500/15 border-blue-500/30 text-blue-300" },
  info:     { dot: "bg-zinc-500", text: "text-zinc-400", badge: "bg-zinc-500/15 border-zinc-500/30 text-zinc-400" },
} as const;

function formatTimestamp(ts: string): string {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return ts;
  }
}

export function ForensicTimeline({ events }: ForensicTimelineProps) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? events : events.slice(0, 8);

  if (!events || events.length === 0) return null;

  return (
    <div className="glass-panel p-5">
      <div className="flex items-center gap-2.5 mb-4">
        <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center">
          <Clock className="w-4 h-4 text-cyan-400" />
        </div>
        <div>
          <h3 className="font-bold text-sm text-white tracking-tight">Forensic Event Timeline</h3>
          <p className="text-[10px] text-zinc-500 font-mono">{events.length} events reconstructed</p>
        </div>
      </div>

      <div className="relative space-y-0">
        {/* Vertical line */}
        <div className="absolute left-[11px] top-2 bottom-2 w-[1px] bg-white/5" />

        {visible.map((evt, i) => {
          const sev = (evt.severity || "info") as keyof typeof SEV_CONFIG;
          const cfg = SEV_CONFIG[sev] ?? SEV_CONFIG.info;
          const isExpanded = expanded === i;
          const hasMetadata = evt.metadata && Object.keys(evt.metadata).length > 0;

          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: i * 0.04 }}
              className="relative flex gap-4 pb-4"
            >
              {/* Dot */}
              <div className={`mt-1 w-[9px] h-[9px] rounded-full shrink-0 z-10 ${cfg.dot}`} />

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-0.5">
                  <span className={`text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 rounded border ${cfg.badge}`}>
                    {evt.category}
                  </span>
                  <span className="text-[10px] font-mono text-zinc-600">
                    {formatTimestamp(evt.timestamp)}
                  </span>
                </div>
                <p className="text-[11px] text-zinc-300 leading-relaxed">{evt.description}</p>

                {hasMetadata && (
                  <button
                    onClick={() => setExpanded(isExpanded ? null : i)}
                    className="flex items-center gap-1 mt-1 text-[10px] text-zinc-600 hover:text-zinc-400 transition-colors"
                  >
                    {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    {isExpanded ? "Hide" : "Details"}
                  </button>
                )}

                {isExpanded && evt.metadata && (
                  <div className="mt-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                    {Object.entries(evt.metadata)
                      .filter(([, v]) => v !== null && v !== undefined && v !== "")
                      .map(([k, v]) => (
                        <div key={k} className="flex gap-2 text-[10px] font-mono">
                          <span className="text-zinc-600 min-w-[100px] shrink-0">{k}:</span>
                          <span className="text-zinc-400 truncate">{String(v)}</span>
                        </div>
                      ))}
                  </div>
                )}
              </div>
            </motion.div>
          );
        })}
      </div>

      {events.length > 8 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="mt-2 text-[10px] font-mono text-zinc-500 hover:text-zinc-300 transition-colors flex items-center gap-1"
        >
          {showAll ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          {showAll ? "Show less" : `Show ${events.length - 8} more events`}
        </button>
      )}
    </div>
  );
}