"use client";

import React from "react";
import { ShieldCheck, Cpu } from "lucide-react";

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-white/10 mt-16 py-8 px-6 bg-black/75 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-zinc-400 text-xs font-mono">
        <div className="flex items-center gap-3">
          <div className="w-6 h-6 rounded-lg bg-red-500/20 border border-red-500/30 flex items-center justify-center text-red-400">
            <ShieldCheck className="w-3.5 h-3.5" />
          </div>
          <span className="text-zinc-300">
            SheildMail <span className="text-red-400 font-bold">v3.2</span> • Enterprise Threat Defense & Forensic Engine
          </span>
        </div>

        <div className="flex items-center gap-6 text-[11px]">
          <span className="flex items-center gap-1.5 text-zinc-400">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            NEURAL THREAT CORE
          </span>

          <span className="flex items-center gap-1.5 text-zinc-300">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            ZERO-TRUST SECURE
          </span>
        </div>
      </div>
    </footer>
  );
};
