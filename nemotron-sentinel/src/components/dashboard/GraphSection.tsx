"use client";

import React, { useMemo } from "react";
import { motion } from "framer-motion";
import { Network, GitBranch, Layers } from "lucide-react";
import { GraphData } from "@/types/threat-intel";
import { NetworkGraphData } from "@/types/network-graph-3d";
import { SectionHeader } from "@/components/dashboard/SectionHeader";
import { NetworkGraphContainer } from "@/components/3d/NetworkGraphContainer";

interface GraphSectionProps {
  graphData: GraphData;
}

export const GraphSection: React.FC<GraphSectionProps> = ({ graphData }) => {
  const legendItems = [
    { label: "THREAT / EMAIL ARTIFACT", color: "#ef4444", dotGlow: "0 0 10px #ef4444" },
    { label: "SPOOFED DOMAIN / C2", color: "#38bdf8", dotGlow: "0 0 10px #38bdf8" },
    { label: "HOSTING IP SUB-NET", color: "#f59e0b", dotGlow: "0 0 10px #f59e0b" },
    { label: "STANDARD ENDPOINT", color: "#ffffff", dotGlow: "0 0 10px #ffffff" },
  ];

  // Map 2D or arbitrary backend telemetry into rich 3D enterprise network format
  const formatted3DData: NetworkGraphData = useMemo(() => {
    return {
      nodes: graphData.nodes.map((node) => ({
        id: node.id,
        name: node.id,
        group: node.group,
        status:
          node.group === 1
            ? "critical"
            : node.group === 4
            ? "alert"
            : node.group === 2
            ? "cold"
            : "normal",
        metadata: {
          threatType:
            node.group === 1
              ? "SPEAR-PHISHING VECTOR"
              : node.group === 2
              ? "SPOOFED DOMAIN / C2"
              : node.group === 3
              ? "BOTNET HOSTING IP"
              : "SUSPICIOUS GEOLOCATION",
          riskScore:
            node.group === 1 ? 95.0 : node.group === 2 ? 92.5 : node.group === 3 ? 88.0 : 84.0,
          protocol:
            node.group === 1 ? "SMTP / TLS 1.3" : node.group === 2 ? "HTTPS / Port 443" : "TCP",
          description: `Entity correlated in SheildMail telemetry pipeline (${node.label || node.id})`,
        },
      })),
      links: graphData.links.map((link) => ({
        source: typeof link.source === "object" ? (link.source as any).id : link.source,
        target: typeof link.target === "object" ? (link.target as any).id : link.target,
        label: link.label,
        value: 3,
        activeFlow: true,
      })),
    };
  }, [graphData]);

  return (
    <motion.section
      initial={{ opacity: 0, y: 25 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.3 }}
      className="space-y-4"
    >
      <SectionHeader
        title="3D Neural Graph Correlation"
        icon={<Network className="w-5 h-5 text-red-400" />}
        subtitle="Multi-hop entity correlation architecture: Email → Sender Domain → Resolved IP → Geolocation"
        badge="3D WEBGL R3F"
        action={
          <div className="flex items-center gap-3 text-xs font-mono text-zinc-400">
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-black/60 border border-white/10">
              <Layers className="w-3.5 h-3.5 text-red-400" />
              <span>NODES: {graphData.nodes.length}</span>
            </span>
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-black/60 border border-white/10">
              <GitBranch className="w-3.5 h-3.5 text-red-400" />
              <span>EDGES: {graphData.links.length}</span>
            </span>
          </div>
        }
      />

      <div className="glass-panel p-4 md:p-5">
        {/* 3D Force-Directed Network Graph */}
        <NetworkGraphContainer initialData={formatted3DData} />

        {/* Tactical Legend & Controls info */}
        <div className="mt-4 pt-3 border-t border-white/5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-4">
            {legendItems.map((item) => (
              <div key={item.label} className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{
                    backgroundColor: item.color,
                    boxShadow: item.dotGlow,
                  }}
                />
                <span className="text-zinc-300 text-[11px]">{item.label}</span>
              </div>
            ))}
          </div>

          <span className="text-zinc-500 text-[11px]">
            Left Click: Orbit • Right Click: Pan • Scroll: Zoom • Hover: Telemetry
          </span>
        </div>
      </div>
    </motion.section>
  );
};
