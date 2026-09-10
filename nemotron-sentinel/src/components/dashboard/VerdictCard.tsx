"use client";
import React from "react";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, CheckCircle2, XCircle, Info, ChevronRight, Lock } from "lucide-react";
import { AnalysisResponse, RiskBreakdownItem } from "@/types/threat-intel";

interface VerdictCardProps {
  data: AnalysisResponse;
}

const LEVEL_CONFIG = {
  CRITICAL: {
    bg: "bg-red-950/60",
    border: "border-red-500/60",
    glow: "shadow-[0_0_40px_rgba(239,68,68,0.35)]",
    text: "text-red-400",
    badge: "bg-red-500/20 border-red-500/40 text-red-300",
    bar: "bg-red-500",
    icon: XCircle,
  },
  HIGH: {
    bg: "bg-orange-950/50",
    border: "border-orange-500/50",
    glow: "shadow-[0_0_35px_rgba(249,115,22,0.25)]",
    text: "text-orange-400",
    badge: "bg-orange-500/20 border-orange-500/40 text-orange-300",
    bar: "bg-orange-500",
    icon: AlertTriangle,
  },
  MEDIUM: {
    bg: "bg-yellow-950/40",
    border: "border-yellow-500/40",
    glow: "shadow-[0_0_30px_rgba(234,179,8,0.2)]",
    text: "text-yellow-400",
    badge: "bg-yellow-500/20 border-yellow-500/40 text-yellow-300",
    bar: "bg-yellow-500",
    icon: AlertTriangle,
  },
  LOW: {
    bg: "bg-emerald-950/40",
    border: "border-emerald-500/40",
    glow: "shadow-[0_0_30px_rgba(16,185,129,0.15)]",
    text: "text-emerald-400",
    badge: "bg-emerald-500/20 border-emerald-500/40 text-emerald-300",
    bar: "bg-emerald-500",
    icon: CheckCircle2,
  },
} as const;

const CATEGORY_COLORS: Record<string, string> = {
  auth: "text-red-400",
  header: "text-orange-400",
  ioc: "text-purple-400",
  origin: "text-cyan-400",
  smtp: "text-yellow-400",
  threat_intel: "text-pink-400",
};

export function VerdictCard({ data }: VerdictCardProps) {
  const level = (data.risk_level || "LOW") as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  const cfg = LEVEL_CONFIG[level] ?? LEVEL_CONFIG.LOW;
  const VerdictIcon = cfg.icon;
  const score = data.risk_score ?? 0;
  const confidence = Math.round((data.confidence ?? 0) * 100);
  const breakdown = data.risk_breakdown || [];
  const evidence = data.primary_evidence || [];
  const actions = data.recommended_actions || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className={`rounded-2xl border p-5 ${cfg.bg} ${cfg.border} ${cfg.glow}`}
    >
      {/* Header Row */}
      <div className="flex flex-wrap items-start justify-between gap-4 mb-5">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${cfg.badge}`}>
            <VerdictIcon className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest mb-0.5">FORENSIC VERDICT</p>
            <h2 className={`font-extrabold text-base tracking-tight ${cfg.text}`}>
              {data.verdict || `${level} RISK`}
            </h2>
          </div>
        </div>

        {/* Risk Score Pill */}
        <div className="flex flex-col items-end gap-1">
          <div className={`px-4 py-1.5 rounded-full border font-mono font-extrabold text-2xl ${cfg.badge}`}>
            {score}<span className="text-sm font-normal opacity-70">/100</span>
          </div>
          <p className="text-[10px] text-zinc-500 font-mono">RISK SCORE &bull; CONFIDENCE {confidence}%</p>
        </div>
      </div>

      {/* Risk Score Bar */}
      <div className="w-full h-2 rounded-full bg-white/5 mb-5 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.9, ease: "easeOut", delay: 0.2 }}
          className={`h-full rounded-full ${cfg.bar}`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Left: Risk Breakdown */}
        {breakdown.length > 0 && (
          <div>
            <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest mb-2.5 flex items-center gap-1.5">
              <Shield className="w-3 h-3" /> RISK FACTORS BREAKDOWN
            </p>
            <div className="space-y-2">
              {breakdown.map((item: RiskBreakdownItem, i) => (
                <div key={i} className="flex items-start justify-between gap-3 py-2 px-3 rounded-lg bg-white/[0.03] border border-white/5">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <span className={`text-[10px] font-mono uppercase font-bold ${CATEGORY_COLORS[item.category] || "text-zinc-400"}`}>
                        [{item.category}]
                      </span>
                      <span className="text-[11px] font-semibold text-zinc-200 truncate">{item.factor}</span>
                    </div>
                    <p className="text-[10px] text-zinc-500 leading-relaxed">{item.reason}</p>
                  </div>
                  <span className={`shrink-0 text-xs font-mono font-bold ${cfg.text} px-2 py-0.5 rounded bg-white/5`}>
                    +{item.points}pts
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Right: Evidence + Actions */}
        <div className="space-y-4">
          {/* Primary Evidence */}
          {evidence.length > 0 && (
            <div>
              <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <Info className="w-3 h-3" /> PRIMARY EVIDENCE
              </p>
              <ul className="space-y-1.5">
                {evidence.map((e, i) => (
                  <li key={i} className="flex items-start gap-2 text-[11px] text-zinc-300 font-mono">
                    <ChevronRight className={`w-3 h-3 mt-0.5 shrink-0 ${cfg.text}`} />
                    <span className="leading-relaxed">{e}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommended Actions */}
          {actions.length > 0 && (
            <div>
              <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <Lock className="w-3 h-3" /> RECOMMENDED ACTIONS
              </p>
              <ul className="space-y-1.5">
                {actions.map((a, i) => (
                  <li key={i} className="flex items-start gap-2 text-[11px] text-zinc-300">
                    <span className={`w-4 h-4 rounded-full text-[9px] flex items-center justify-center shrink-0 mt-0.5 font-mono font-bold ${cfg.badge}`}>
                      {i + 1}
                    </span>
                    <span className="leading-relaxed">{a}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Integrity */}
          {(data.email_sha256 || data.case_id) && (
            <div className="pt-3 border-t border-white/5">
              <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest mb-2">EVIDENCE INTEGRITY</p>
              {data.case_id && (
                <p className="text-[10px] font-mono text-zinc-400">
                  <span className="text-zinc-600">CASE ID: </span>
                  <span className="text-emerald-400 font-bold">{data.case_id}</span>
                </p>
              )}
              {data.email_sha256 && (
                <p className="text-[10px] font-mono text-zinc-500 truncate mt-0.5">
                  <span className="text-zinc-600">SHA-256: </span>
                  <span className="text-zinc-400">{data.email_sha256.slice(0, 32)}...</span>
                </p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Limitations notice */}
      {data.limitations && (
        <p className="mt-4 text-[10px] text-zinc-600 font-mono leading-relaxed border-t border-white/5 pt-3">
          ⓘ {data.limitations}
        </p>
      )}
    </motion.div>
  );
}