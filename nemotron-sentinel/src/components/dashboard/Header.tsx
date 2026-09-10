"use client";

import React from "react";
import { Shield, Cpu, Wifi, WifiOff, Terminal } from "lucide-react";
import { motion } from "framer-motion";

interface HeaderProps {
  isBackendLive: boolean;
  scanId?: string;
  onRunDemo?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  isBackendLive,
  scanId,
  onRunDemo,
}) => {
  return (
    <header className="relative z-30 border-b border-white/10 backdrop-blur-2xl bg-black/75 sticky top-0">
      {/* Top subtle red & cold highlight line */}
      <div className="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-[#ef4444]/60 to-transparent" />

      <div className="max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        {/* Brand identity */}
        <div className="flex items-center gap-3.5">
          <motion.div
            whileHover={{ scale: 1.05, rotate: 5 }}
            transition={{ type: "spring", stiffness: 400, damping: 17 }}
            className="w-11 h-11 rounded-xl bg-gradient-to-br from-[#ff5555] via-[#ef4444] to-[#991b1b] flex items-center justify-center shadow-[0_0_25px_rgba(239,68,68,0.45)] border border-white/20 shrink-0"
          >
            <Shield className="w-6 h-6 text-white stroke-[2.5]" />
          </motion.div>

          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-xl tracking-tight bg-gradient-to-r from-white via-slate-100 to-[#fca5a5] bg-clip-text text-transparent">
                SheildMail
              </h1>
              <span className="text-[10px] font-mono font-bold tracking-widest px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/30 hidden sm:inline-block">
                v3.2 ENTERPRISE
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 font-mono tracking-wider uppercase flex items-center gap-1.5">
              <span className="text-zinc-300">Enterprise Threat Defense</span>
              <span className="text-zinc-600">•</span>
              <span className="text-red-400 font-semibold">Autonomous Forensics</span>
            </p>
          </div>
        </div>

        {/* Telemetry status & Actions */}
        <div className="flex items-center gap-3">
          {/* Active Engine pill */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-black/60 border border-white/10 text-xs font-mono">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-zinc-400">CORE:</span>
            <span className="text-white font-semibold">Neural Threat Engine</span>
          </div>

          {/* Backend Status indicator */}
          <div
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl border text-xs font-mono transition-colors ${
              isBackendLive
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                : "bg-red-500/10 border-red-500/30 text-red-400"
            }`}
          >
            <span className="relative flex h-2 w-2">
              <span
                className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  isBackendLive ? "bg-emerald-400" : "bg-red-400"
                }`}
              />
              <span
                className={`relative inline-flex rounded-full h-2 w-2 ${
                  isBackendLive ? "bg-emerald-500" : "bg-red-500"
                }`}
              />
            </span>
            {isBackendLive ? (
              <span className="flex items-center gap-1 font-semibold">
                <Wifi className="w-3.5 h-3.5" /> API ONLINE
              </span>
            ) : (
              <span className="flex items-center gap-1 font-semibold">
                <WifiOff className="w-3.5 h-3.5" /> DEMO MODE
              </span>
            )}
          </div>

          {/* Quick Demo button */}
          {onRunDemo && (
            <motion.button
              whileHover={{ scale: 1.03, y: -1 }}
              whileTap={{ scale: 0.97 }}
              onClick={onRunDemo}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-red-500/20 to-red-600/10 border border-red-500/40 text-red-300 hover:text-white hover:bg-red-500/30 text-xs font-mono font-semibold transition-all shadow-[0_0_15px_rgba(239,68,68,0.15)]"
            >
              <Terminal className="w-3.5 h-3.5 text-red-400" />
              <span>TEST SAMPLE</span>
            </motion.button>
          )}
        </div>
      </div>
    </header>
  );
};
