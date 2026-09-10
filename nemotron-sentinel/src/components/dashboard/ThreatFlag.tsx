"use client";

import React from "react";
import { motion } from "framer-motion";
import { AlertTriangle } from "lucide-react";

interface ThreatFlagProps {
  flag: string;
}

export const ThreatFlag: React.FC<ThreatFlagProps> = ({ flag }) => (
  <motion.span
    whileHover={{ scale: 1.04, y: -1 }}
    transition={{ duration: 0.15 }}
    className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono font-medium shadow-[0_0_15px_rgba(239,68,68,0.15)] hover:border-red-500/50 hover:bg-red-500/20 transition-all cursor-default"
  >
    <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 animate-pulse" />
    <span className="tracking-wide truncate">{flag}</span>
  </motion.span>
);
