"use client";

import React, { useState } from "react";
import dynamic from "next/dynamic";
import { GlossySkeleton } from "@/components/ui/GlossySkeleton";
import { useNetworkGraphData, defaultEnterpriseGraphData } from "@/hooks/useNetworkGraphData";
import { NetworkGraphData, NetworkNode } from "@/types/network-graph-3d";
import { RefreshCw, Radio, Layers, GitBranch, Maximize2, Minimize2 } from "lucide-react";

// Dynamic import with SSR disabled and GlossySkeleton fallback
const NetworkGraph3D = dynamic(
  () => import("@/components/3d/NetworkGraph3D").then((mod) => mod.NetworkGraph3D),
  {
    ssr: false,
    loading: () => (
      <GlossySkeleton
        height={520}
        label="INITIALIZING 3D TOPOLOGY ARCHITECTURE..."
        sublabel="Mounting WebGL context, physics solver & photon stream"
      />
    ),
  }
);

interface NetworkGraphContainerProps {
  initialData?: NetworkGraphData;
  apiEndpoint?: string;
  websocketUrl?: string;
  pollIntervalMs?: number;
  onNodeClick?: (node: NetworkNode) => void;
  className?: string;
}

export const NetworkGraphContainer: React.FC<NetworkGraphContainerProps> = ({
  initialData,
  apiEndpoint,
  websocketUrl,
  pollIntervalMs = 0,
  onNodeClick,
  className = "",
}) => {
  const { data, loading, isLive, refresh } = useNetworkGraphData({
    initialData,
    apiEndpoint,
    websocketUrl,
    pollIntervalMs,
  });

  const [isFullscreen, setIsFullscreen] = useState(false);

  return (
    <div className={`relative ${isFullscreen ? "fixed inset-4 z-50 bg-black/95 p-4 rounded-2xl border border-red-500/40 shadow-2xl flex flex-col" : ""} ${className}`}>
      {/* 3D Network Graph Canvas */}
      <NetworkGraph3D
        nodes={data.nodes}
        links={data.links}
        onNodeClick={onNodeClick}
        className={isFullscreen ? "h-full flex-1" : "h-[520px]"}
      />

      {/* Floating Bottom Action Toolbar */}
      <div className="absolute bottom-4 right-4 z-10 flex items-center gap-2.5 font-mono text-xs">
        {/* Live Stream Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-black/80 border border-white/10 backdrop-blur-xl text-zinc-300">
          <Radio className={`w-3.5 h-3.5 ${isLive ? "text-emerald-400 animate-pulse" : "text-red-400"}`} />
          <span className="text-[11px] font-semibold">{isLive ? "STREAM LIVE" : "TELEMETRY CACHED"}</span>
        </div>

        {/* Refresh Action */}
        <button
          onClick={() => refresh()}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-black/80 hover:bg-white/10 border border-white/10 text-zinc-300 hover:text-white backdrop-blur-xl transition-colors"
          title="Refresh graph telemetry"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-red-400" : ""}`} />
          <span className="text-[11px] hidden sm:inline">REFRESH</span>
        </button>

        {/* Fullscreen Toggle */}
        <button
          onClick={() => setIsFullscreen(!isFullscreen)}
          className="flex items-center justify-center w-8 h-8 rounded-xl bg-black/80 hover:bg-white/10 border border-white/10 text-zinc-300 hover:text-white backdrop-blur-xl transition-colors"
          title={isFullscreen ? "Exit fullscreen" : "Expand 3D view"}
        >
          {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
        </button>
      </div>
    </div>
  );
};

export default NetworkGraphContainer;
