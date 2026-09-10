"use client";

import React from "react";
import { motion } from "framer-motion";
import { CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { AuthStatus } from "@/types/threat-intel";

interface StatusBadgeProps {
  label: string;
  status: AuthStatus;
  description: string;
  recordValue?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  label,
  status,
  description,
  recordValue,
}) => {
  const isPass = status === "pass";
  const isFail = status === "fail";

  const getStyles = () => {
    if (isPass) {
      return {
        cardBorder: "border-emerald-500/30 hover:border-emerald-500/50",
        badgeBg: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
        iconBg: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
        icon: <CheckCircle2 className="w-6 h-6 text-emerald-400" />,
        shadow: "hover:shadow-[0_0_25px_rgba(16,185,129,0.2)]",
      };
    }
    if (isFail) {
      return {
        cardBorder: "border-red-500/30 hover:border-red-500/50",
        badgeBg: "bg-red-500/15 text-red-400 border-red-500/40",
        iconBg: "bg-red-500/20 text-red-400 border-red-500/30",
        icon: <XCircle className="w-6 h-6 text-red-400" />,
        shadow: "hover:shadow-[0_0_25px_rgba(239,68,68,0.2)]",
      };
    }
    return {
      cardBorder: "border-amber-500/30 hover:border-amber-500/50",
      badgeBg: "bg-amber-500/15 text-amber-400 border-amber-500/40",
      iconBg: "bg-amber-500/20 text-amber-400 border-amber-500/30",
      icon: <AlertCircle className="w-6 h-6 text-amber-400" />,
      shadow: "hover:shadow-[0_0_25px_rgba(245,158,11,0.2)]",
    };
  };

  const styles = getStyles();

  return (
    <motion.div
      whileHover={{ y: -3, scale: 1.01 }}
      transition={{ duration: 0.2 }}
      className={`glass-card p-4 flex items-center gap-4 transition-all duration-300 border ${styles.cardBorder} ${styles.shadow}`}
    >
      <div
        className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 border ${styles.iconBg}`}
      >
        {styles.icon}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2.5 mb-1">
          <span className="font-mono text-base font-bold tracking-wider text-white">
            {label}
          </span>
          <span
            className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold tracking-wider border ${styles.badgeBg}`}
          >
            {status.toUpperCase()}
          </span>
        </div>
        <p className="text-zinc-400 text-xs font-mono line-clamp-1">{description}</p>
        {recordValue && (
          <p className="text-[11px] text-zinc-500 font-mono mt-0.5 truncate">
            {recordValue}
          </p>
        )}
      </div>
    </motion.div>
  );
};
