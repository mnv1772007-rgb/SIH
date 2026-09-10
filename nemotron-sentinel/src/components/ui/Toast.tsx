"use client";

import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, Info, CheckCircle2, X, WifiOff } from "lucide-react";

export interface ToastMessage {
  id: string;
  type: "warning" | "error" | "info" | "success";
  title: string;
  description?: string;
  duration?: number;
}

interface ToastProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastProps> = ({ toasts, onDismiss }) => {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 max-w-md w-full pointer-events-none px-4 sm:px-0">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  );
};

const ToastItem: React.FC<{
  toast: ToastMessage;
  onDismiss: (id: string) => void;
}> = ({ toast, onDismiss }) => {
  const duration = toast.duration ?? 6000;

  useEffect(() => {
    if (duration > 0) {
      const timer = setTimeout(() => {
        onDismiss(toast.id);
      }, duration);
      return () => clearTimeout(timer);
    }
  }, [toast.id, duration, onDismiss]);

  const getTheme = () => {
    switch (toast.type) {
      case "warning":
        return {
          border: "border-red-500/60",
          glow: "shadow-[0_0_25px_rgba(239,68,68,0.3)]",
          icon: <WifiOff className="w-5 h-5 text-red-400" />,
          badge: "DEMO MODE",
          badgeColor: "bg-red-500/20 text-red-400 border-red-500/40",
          accentColor: "bg-red-500",
        };
      case "error":
        return {
          border: "border-red-500/60",
          glow: "shadow-[0_0_25px_rgba(239,68,68,0.25)]",
          icon: <AlertTriangle className="w-5 h-5 text-red-400" />,
          badge: "ALERT",
          badgeColor: "bg-red-500/20 text-red-400 border-red-500/40",
          accentColor: "bg-red-500",
        };
      case "success":
        return {
          border: "border-emerald-500/60",
          glow: "shadow-[0_0_25px_rgba(16,185,129,0.25)]",
          icon: <CheckCircle2 className="w-5 h-5 text-emerald-400" />,
          badge: "VERIFIED",
          badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
          accentColor: "bg-emerald-500",
        };
      default:
        return {
          border: "border-cyan-500/60",
          glow: "shadow-[0_0_25px_rgba(6,182,212,0.25)]",
          icon: <Info className="w-5 h-5 text-cyan-400" />,
          badge: "INFO",
          badgeColor: "bg-cyan-500/20 text-cyan-400 border-cyan-500/40",
          accentColor: "bg-cyan-500",
        };
    }
  };

  const theme = getTheme();

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 30, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, x: 80, scale: 0.9 }}
      transition={{ type: "spring", stiffness: 350, damping: 25 }}
      className={`pointer-events-auto relative overflow-hidden rounded-2xl bg-black/85 backdrop-blur-2xl border ${theme.border} ${theme.glow} p-4 text-white shadow-2xl`}
    >
      {/* Top subtle highlight */}
      <div className="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-white/20 to-transparent" />

      <div className="flex items-start gap-3.5">
        <div className="p-2 rounded-xl bg-black/60 border border-white/10 shrink-0">
          {theme.icon}
        </div>

        <div className="flex-1 min-w-0 pr-2">
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`text-[10px] font-mono font-bold tracking-widest px-2 py-0.5 rounded-full border ${theme.badgeColor}`}
            >
              {theme.badge}
            </span>
            <h4 className="font-semibold text-sm tracking-tight text-white truncate">
              {toast.title}
            </h4>
          </div>

          {toast.description && (
            <p className="text-xs text-zinc-300/80 leading-relaxed font-mono">
              {toast.description}
            </p>
          )}
        </div>

        <button
          onClick={() => onDismiss(toast.id)}
          className="p-1 rounded-lg text-zinc-400 hover:text-white hover:bg-white/10 transition-colors shrink-0"
          aria-label="Dismiss notification"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Progress timer bar */}
      {duration > 0 && (
        <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-white/5 overflow-hidden">
          <motion.div
            initial={{ width: "100%" }}
            animate={{ width: "0%" }}
            transition={{ duration: duration / 1000, ease: "linear" }}
            className={`h-full ${theme.accentColor}`}
          />
        </div>
      )}
    </motion.div>
  );
};
