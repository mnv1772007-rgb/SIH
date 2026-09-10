"use client";

import React from "react";
import { motion } from "framer-motion";
import { Activity } from "lucide-react";

interface GlossySkeletonProps {
  height?: string | number;
  label?: string;
  sublabel?: string;
}

export const GlossySkeleton: React.FC<GlossySkeletonProps> = ({
  height = 450,
  label = "INITIALIZING 3D TELEMETRY ENGINE...",
  sublabel = "Loading shader pipeline & WebGL context",
}) => {
  return (
    <div
      style={{ height }}
      className="relative w-full rounded-2xl overflow-hidden bg-black/70 backdrop-blur-2xl border border-white/10 flex flex-col items-center justify-center p-6 select-none"
    >
      {/* Background Cyber Grid */}
      <div
        className="absolute inset-0 opacity-15"
        style={{
          backgroundImage: `
            linear-gradient(rgba(239, 68, 68, 0.15) 1px, transparent 1px),
            linear-gradient(90deg, rgba(239, 68, 68, 0.15) 1px, transparent 1px)
          `,
          backgroundSize: "32px 32px",
        }}
      />

      {/* Radial red glow */}
      <div className="absolute w-64 h-64 rounded-full bg-red-500/10 blur-3xl pointer-events-none" />

      {/* Rotating Cyber Radar rings (Ruby Red & Cold Ice) */}
      <div className="relative w-32 h-32 flex items-center justify-center mb-6">
        {/* Outer dashed ring */}
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
          className="absolute inset-0 rounded-full border border-dashed border-red-500/40"
        />

        {/* Middle pulsing ring */}
        <motion.div
          animate={{ scale: [1, 1.15, 1], opacity: [0.3, 0.7, 0.3] }}
          transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
          className="absolute inset-3 rounded-full border border-red-500/60 shadow-[0_0_15px_rgba(239,68,68,0.35)]"
        />

        {/* Inner fast spin ring */}
        <motion.div
          animate={{ rotate: -360 }}
          transition={{ duration: 6, repeat: Infinity, ease: "linear" }}
          className="absolute inset-6 rounded-full border-t-2 border-r-2 border-transparent border-t-red-400 border-r-red-400/60"
        />

        {/* Center core pulse */}
        <div className="w-10 h-10 rounded-xl bg-black/80 border border-red-500/80 shadow-[0_0_20px_rgba(239,68,68,0.5)] flex items-center justify-center">
          <Activity className="w-5 h-5 text-red-400 animate-pulse" />
        </div>
      </div>

      {/* Status telemetry readout */}
      <div className="text-center relative z-10 space-y-2 max-w-sm">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono tracking-wider">
          <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
          <span>GPU ACCELERATED</span>
        </div>

        <p className="font-mono text-sm font-semibold text-zinc-100 tracking-wider">
          {label}
        </p>

        <p className="font-mono text-xs text-zinc-400">
          {sublabel}
        </p>

        {/* Scanning progress animation */}
        <div className="w-48 h-1.5 bg-black/60 rounded-full mx-auto overflow-hidden border border-white/10 mt-3">
          <motion.div
            animate={{ x: ["-100%", "100%"] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: "easeInOut" }}
            className="w-1/2 h-full bg-gradient-to-r from-transparent via-red-500 to-transparent rounded-full shadow-[0_0_10px_#ef4444]"
          />
        </div>
      </div>
    </div>
  );
};
