"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { 
  ShieldAlert, 
  Activity, 
  Zap, 
  Globe2, 
  Lock, 
  Cpu, 
  CheckCircle2, 
  Radio, 
  TrendingUp, 
  Layers 
} from "lucide-react";

interface ThreatEvent {
  id: string;
  timeAgo: string;
  type: string;
  target: string;
  origin: string;
  severity: "CRITICAL" | "HIGH";
  action: string;
}

export const GlobalThreatFeedSection: React.FC = () => {
  const [feedIndex, setFeedIndex] = useState(0);

  const initialFeed: ThreatEvent[] = [
    {
      id: "EVT-9921",
      timeAgo: "3s ago",
      type: "Microsoft 365 AiTM Phish",
      target: "finance-lead@defense-corp.com",
      origin: "RU (Novosibirsk, AS12345)",
      severity: "CRITICAL",
      action: "QUARANTINED",
    },
    {
      id: "EVT-9920",
      timeAgo: "14s ago",
      type: "Urgent Wire BEC Fraud",
      target: "cfo-desk@global-logistics.eu",
      origin: "NG (Lagos, AS37100)",
      severity: "HIGH",
      action: "INTERCEPTED",
    },
    {
      id: "EVT-9919",
      timeAgo: "32s ago",
      type: "Google Workspace SVG Harvest",
      target: "hr-ops@health-networks.org",
      origin: "NL (Amsterdam, AS49505)",
      severity: "CRITICAL",
      action: "BLOCKED",
    },
    {
      id: "EVT-9918",
      timeAgo: "58s ago",
      type: "DocuSign Homoglyph Lure",
      target: "legal-counsel@fintech-inc.com",
      origin: "US (Ashburn, AS14618)",
      severity: "HIGH",
      action: "NEUTRALIZED",
    },
    {
      id: "EVT-9917",
      timeAgo: "1m ago",
      type: "Okta SSO Token Hijacking",
      target: "devops-admin@cloud-scale.io",
      origin: "RO (Bucharest, AS20858)",
      severity: "CRITICAL",
      action: "QUARANTINED",
    },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setFeedIndex((prev) => (prev + 1) % initialFeed.length);
    }, 4000);
    return () => clearInterval(timer);
  }, [initialFeed.length]);

  const metrics = [
    {
      title: "GLOBAL EMAILS INSPECTED TODAY",
      value: "1,492,080",
      sub: "+14.2% vs 7-day median",
      icon: <Activity className="w-4 h-4 text-cyan-400" />,
      color: "text-cyan-400",
    },
    {
      title: "NEURAL DETECTION PRECISION",
      value: "99.98%",
      sub: "False positive rate < 0.001%",
      icon: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
      color: "text-emerald-400",
    },
    {
      title: "ZERO-DAY OUTBREAKS BLOCKED",
      value: "4,819",
      sub: "Active threat campaigns halted",
      icon: <ShieldAlert className="w-4 h-4 text-red-400" />,
      color: "text-red-400",
    },
    {
      title: "MEDIAN DEFENSE LATENCY",
      value: "12.4ms",
      sub: "Real-time edge neural inference",
      icon: <Zap className="w-4 h-4 text-amber-400" />,
      color: "text-amber-400",
    },
  ];

  return (
    <section className="space-y-6 mt-8">
      {/* 4 Key Enterprise Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map((m, idx) => (
          <div
            key={idx}
            className="glass-panel p-4 border border-white/10 relative overflow-hidden group hover:border-white/20 transition-all"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono text-zinc-400 font-bold uppercase tracking-wider">
                {m.title}
              </span>
              <div className="w-7 h-7 rounded-lg bg-black/60 border border-white/10 flex items-center justify-center">
                {m.icon}
              </div>
            </div>

            <p className={`text-2xl font-mono font-bold ${m.color} tracking-tight`}>
              {m.value}
            </p>

            <p className="text-[11px] font-mono text-zinc-400 mt-1 flex items-center gap-1">
              <TrendingUp className="w-3 h-3 text-emerald-400" />
              <span>{m.sub}</span>
            </p>
          </div>
        ))}
      </div>

      {/* Real-Time SOC Defense Stream & Ticker */}
      <div className="glass-panel p-5 border border-white/10">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-white/10">
          <div className="flex items-center gap-2.5">
            <Radio className="w-4 h-4 text-red-400 animate-pulse" />
            <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider">
              Real-Time Global Intercept Telemetry Stream
            </h3>
          </div>

          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span className="text-[11px] font-mono text-emerald-400 font-bold">
              LIVE NETWORK INTERCEPT FEED
            </span>
          </div>
        </div>

        <div className="space-y-2 font-mono">
          {initialFeed.map((evt, idx) => {
            const isHighlight = idx === feedIndex;
            return (
              <motion.div
                key={evt.id}
                animate={{
                  backgroundColor: isHighlight ? "rgba(239, 68, 68, 0.12)" : "rgba(0, 0, 0, 0.35)",
                  borderColor: isHighlight ? "rgba(239, 68, 68, 0.4)" : "rgba(255, 255, 255, 0.06)",
                }}
                className="p-3 rounded-xl border flex flex-wrap items-center justify-between gap-3 text-xs transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="text-zinc-500 font-bold">{evt.timeAgo}</span>
                  <span className="text-red-400 font-bold">{evt.type}</span>
                  <span className="text-zinc-600 hidden sm:inline">&gt;</span>
                  <span className="text-zinc-300 truncate max-w-[200px] hidden md:inline">
                    {evt.target}
                  </span>
                </div>

                <div className="flex items-center gap-3 text-right">
                  <span className="text-zinc-400 hidden sm:inline">{evt.origin}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      evt.action === "QUARANTINED"
                        ? "bg-red-500/20 text-red-400 border border-red-500/30"
                        : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                    }`}
                  >
                    {evt.action}
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Forensic Architecture Feature Highlights */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-panel p-4 border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-red-400">
            <Lock className="w-4 h-4" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              RFC Cryptographic Forensics
            </h4>
          </div>
          <p className="text-xs text-zinc-400 font-mono leading-relaxed">
            Instantaneous cryptographic inspection of SPF, DKIM 2048-bit RSA signatures, and DMARC alignment directives.
          </p>
        </div>

        <div className="glass-panel p-4 border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-cyan-400">
            <Layers className="w-4 h-4" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              3D Neural Graph Correlation
            </h4>
          </div>
          <p className="text-xs text-zinc-400 font-mono leading-relaxed">
            Multi-hop relational entity mapping connecting deceptive sender domains, FastFlux IPs, autonomous systems, and payload C2s.
          </p>
        </div>

        <div className="glass-panel p-4 border border-white/10 space-y-2">
          <div className="flex items-center gap-2 text-emerald-400">
            <Cpu className="w-4 h-4" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Executive PDF Forensics
            </h4>
          </div>
          <p className="text-xs text-zinc-400 font-mono leading-relaxed">
            Export audit-compliant executive incident reports with SHA-256 integrity signatures, IOC tables, and mitigation blueprints.
          </p>
        </div>
      </div>
    </section>
  );
};

export default GlobalThreatFeedSection;
