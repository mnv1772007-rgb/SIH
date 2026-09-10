"use client";

import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, ShieldCheck } from "lucide-react";

interface RiskGaugeProps {
  score: number;
  title?: string;
  subtitle?: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  title = "FORENSIC THREAT INDEX",
  subtitle = "Evaluated via multi-stage forensic heuristics",
}) => {
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const duration = 1200;
    const startTime = performance.now();

    const animateNumber = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayScore(eased * score);

      if (progress < 1) {
        requestAnimationFrame(animateNumber);
      }
    };

    requestAnimationFrame(animateNumber);
  }, [score]);

  const radius = 80;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;

  const getSeverity = () => {
    if (score >= 80) {
      return {
        label: "CRITICAL",
        color: "text-red-400",
        badge: "bg-red-500/20 text-red-400 border-red-500/40",
        glow: "shadow-[0_0_30px_rgba(239,68,68,0.3)]",
        icon: <ShieldAlert className="w-4 h-4 text-red-400" />,
      };
    }
    if (score >= 50) {
      return {
        label: "HIGH",
        color: "text-orange-400",
        badge: "bg-orange-500/20 text-orange-400 border-orange-500/40",
        glow: "shadow-[0_0_30px_rgba(249,115,22,0.3)]",
        icon: <ShieldAlert className="w-4 h-4 text-orange-400" />,
      };
    }
    if (score >= 25) {
      return {
        label: "MEDIUM",
        color: "text-cyan-400",
        badge: "bg-cyan-500/20 text-cyan-400 border-cyan-500/40",
        glow: "shadow-[0_0_30px_rgba(6,182,212,0.3)]",
        icon: <ShieldAlert className="w-4 h-4 text-cyan-400" />,
      };
    }
    return {
      label: "LOW",
      color: "text-emerald-400",
      badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
      glow: "shadow-[0_0_30px_rgba(16,185,129,0.25)]",
      icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
    };
  };

  const severity = getSeverity();

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.92 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5 }}
      className={`glass-panel p-6 flex flex-col items-center justify-center text-center relative overflow-hidden ${severity.glow}`}
    >
      {/* Background radial accent */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-red-500/5 to-transparent pointer-events-none" />

      {/* Header telemetry */}
      <div className="flex items-center gap-2 mb-4">
        <span className="text-xs font-mono tracking-widest text-zinc-400 uppercase">
          {title}
        </span>
      </div>

      {/* SVG Radial Gauge */}
      <div className="relative w-48 h-48 my-2">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 200 200">
          <defs>
            <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="45%" stopColor="#f59e0b" />
              <stop offset="85%" stopColor="#ef4444" />
              <stop offset="100%" stopColor="#991b1b" />
            </linearGradient>
            <filter id="gaugeGlow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="5" result="glow" />
              <feMerge>
                <feMerge in="glow" />
                <feMerge in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Background circle track */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            stroke="rgba(255, 255, 255, 0.06)"
            strokeWidth={strokeWidth}
            fill="none"
          />

          {/* Glowing Animated Arc */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            stroke="url(#riskGradient)"
            strokeWidth={strokeWidth}
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{
              transition: "stroke-dashoffset 1.4s cubic-bezier(0.16, 1, 0.3, 1)",
              filter: "url(#gaugeGlow)",
            }}
          />
        </svg>

        {/* Inner Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="font-mono text-5xl font-extrabold text-white tracking-tighter">
            {displayScore.toFixed(1)}
          </span>
          <span className="text-[11px] font-mono text-zinc-400 tracking-wider mt-0.5">
            / 100.0
          </span>
        </div>
      </div>

      {/* Severity Pill */}
      <div className="mt-4 flex flex-col items-center gap-2">
        <div
          className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold tracking-widest border ${severity.badge}`}
        >
          {severity.icon}
          <span>{severity.label} THREAT DETECTED</span>
        </div>
        <p className="text-xs text-zinc-400 font-mono">
          {subtitle}
        </p>
      </div>
    </motion.div>
  );
};
