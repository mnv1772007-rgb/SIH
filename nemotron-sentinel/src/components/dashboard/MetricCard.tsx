"use client";

import React from "react";
import { motion } from "framer-motion";

interface MetricCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: string;
  trendColor?: "green" | "red" | "blue" | "amber";
  className?: string;
  subtitle?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  icon,
  trend,
  trendColor = "green",
  className = "",
  subtitle,
}) => {
  const getTrendColor = () => {
    switch (trendColor) {
      case "red":
        return "text-red-400 bg-red-500/10 border-red-500/20";
      case "blue":
        return "text-cyan-400 bg-cyan-500/10 border-cyan-500/20";
      case "amber":
        return "text-amber-400 bg-amber-500/10 border-amber-500/20";
      default:
        return "text-red-400 bg-red-500/10 border-red-500/20";
    }
  };

  return (
    <motion.div
      whileHover={{ y: -3, scale: 1.01 }}
      transition={{ duration: 0.2 }}
      className={`glass-card p-5 relative overflow-hidden transition-all duration-300 hover:border-white/20 hover:shadow-[0_10px_30px_rgba(0,0,0,0.6)] ${className}`}
    >
      {/* Top subtle highlight */}
      <div className="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-white/10 to-transparent" />

      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-mono uppercase tracking-wider mb-2">
            <span className="text-red-400">{icon}</span>
            <span className="truncate">{label}</span>
          </div>

          <div className="font-mono text-2xl lg:text-3xl font-bold text-white tracking-tight truncate">
            {value}
          </div>

          {subtitle && (
            <p className="text-xs text-zinc-400 font-mono mt-1 truncate">
              {subtitle}
            </p>
          )}

          {trend && (
            <div className="mt-3 flex items-center">
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-medium border ${getTrendColor()}`}
              >
                {trend}
              </span>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
};
