"use client";

import React from "react";

interface SectionHeaderProps {
  title: string;
  icon: React.ReactNode;
  subtitle?: string;
  action?: React.ReactNode;
  badge?: string;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({
  title,
  icon,
  subtitle,
  action,
  badge = "LIVE TELEMETRY",
}) => (
  <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
    <div className="flex items-center gap-3.5">
      <div className="w-10 h-10 rounded-xl bg-black/60 border border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.2)] flex items-center justify-center text-red-400 shrink-0">
        {icon}
      </div>

      <div>
        <div className="flex items-center gap-2.5">
          <h2 className="text-xl md:text-2xl font-bold text-white tracking-tight">
            {title}
          </h2>
          {badge && (
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold tracking-wider bg-red-500/15 text-red-400 rounded-md border border-red-500/30">
              {badge}
            </span>
          )}
        </div>
        {subtitle && <p className="text-zinc-400 text-xs font-mono mt-0.5">{subtitle}</p>}
      </div>
    </div>

    {action && <div className="shrink-0">{action}</div>}
  </div>
);
