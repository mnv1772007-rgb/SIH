"use client";

import React, { useRef, useState, useEffect } from "react";
import dynamic from "next/dynamic";
import { GlossySkeleton } from "@/components/ui/GlossySkeleton";
import { useResizeObserver } from "@/hooks/useResizeObserver";
import { GraphNode, GraphLink } from "@/types/threat-intel";

// Dynamic import with SSR disabled and GlossySkeleton fallback
const ForceGraph2D = dynamic(
  () => import("react-force-graph-2d").then((mod) => mod.default),
  {
    ssr: false,
    loading: () => (
      <GlossySkeleton
        height={460}
        label="SYNTHESIZING FORCE TOPOLOGY GRAPH..."
        sublabel="Computing entity physics, photon links & spring equilibria"
      />
    ),
  }
);

interface ForceGraphViewProps {
  nodes: GraphNode[];
  links: GraphLink[];
}

export const ForceGraphView: React.FC<ForceGraphViewProps> = ({ nodes, links }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const { width } = useResizeObserver(containerRef, { width: 600, height: 460 });
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  // Red, Cold Ice, Cold Steel & Ruby Geolocation palette
  const colorMap: Record<number, string> = {
    1: "#ef4444", // Email - Vivid Red
    2: "#38bdf8", // Domain/URL - Cold Ice Blue
    3: "#f8fafc", // IP - Cold Steel White
    4: "#b91c1c", // Geo - Deep Ruby Red
  };

  const labelMap: Record<number, string> = {
    1: "EMAIL",
    2: "DOMAIN / URL",
    3: "IP ADDRESS",
    4: "GEOLOCATION",
  };

  const nodeCanvasObject = (
    node: any,
    ctx: CanvasRenderingContext2D,
    globalScale: number
  ) => {
    const radius = 26;
    const x = node.x || 0;
    const y = node.y || 0;
    const color = colorMap[node.group] || "#ef4444";

    // Outer glow halo
    const glowGradient = ctx.createRadialGradient(x, y, 0, x, y, radius * 1.6);
    glowGradient.addColorStop(0, color + "55");
    glowGradient.addColorStop(1, "transparent");
    ctx.fillStyle = glowGradient;
    ctx.beginPath();
    ctx.arc(x, y, radius * 1.6, 0, Math.PI * 2);
    ctx.fill();

    // Node body gradient
    const mainGradient = ctx.createRadialGradient(
      x - radius * 0.3,
      y - radius * 0.3,
      0,
      x,
      y,
      radius
    );
    mainGradient.addColorStop(0, color + "FF");
    mainGradient.addColorStop(0.6, color + "DD");
    mainGradient.addColorStop(1, color + "88");
    ctx.fillStyle = mainGradient;
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fill();

    // Inner specular glass highlight
    ctx.fillStyle = "rgba(255, 255, 255, 0.35)";
    ctx.beginPath();
    ctx.arc(x - radius * 0.3, y - radius * 0.3, radius * 0.45, 0, Math.PI * 2);
    ctx.fill();

    // Node border ring
    ctx.strokeStyle = "rgba(255, 255, 255, 0.5)";
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Primary Text Label (above node)
    ctx.font = `600 ${Math.max(10, 13 / globalScale)}px "JetBrains Mono", monospace`;
    ctx.fillStyle = "#ffffff";
    ctx.textAlign = "center";
    const displayText =
      node.id.length > 20 ? node.id.slice(0, 18) + "..." : node.id;
    ctx.fillText(displayText, x, y - radius - 8 / globalScale);

    // Group Subtitle Badge (below node)
    ctx.font = `700 ${Math.max(8, 10 / globalScale)}px "JetBrains Mono", monospace`;
    ctx.fillStyle = color === "#f8fafc" ? "#cbd5e1" : color;
    ctx.fillText(
      node.label || labelMap[node.group] || "NODE",
      x,
      y + radius + 15 / globalScale
    );
  };

  const linkCanvasObject = (
    link: any,
    ctx: CanvasRenderingContext2D
  ) => {
    if (!link.source || !link.target) return;
    const sx = link.source.x ?? 0;
    const sy = link.source.y ?? 0;
    const tx = link.target.x ?? 0;
    const ty = link.target.y ?? 0;

    // Base connection line (Crimson Red / Cold Slate)
    ctx.strokeStyle = "rgba(239, 68, 68, 0.4)";
    ctx.lineWidth = 1.8;
    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.lineTo(tx, ty);
    ctx.stroke();

    // Flowing animated photon particle
    const time = Date.now() * 0.0012;
    const progress = (time * 0.4) % 1;
    const px = sx + (tx - sx) * progress;
    const py = sy + (ty - sy) * progress;

    ctx.fillStyle = "#ff4d4d";
    ctx.shadowColor = "#ef4444";
    ctx.shadowBlur = 12;
    ctx.beginPath();
    ctx.arc(px, py, 3.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
  };

  const graphData = {
    nodes: nodes.map((n) => ({ ...n })),
    links: links.map((l) => ({ ...l })),
  };

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[460px] rounded-2xl overflow-hidden bg-black/70 backdrop-blur-xl border border-white/10 shadow-[0_0_40px_rgba(0,0,0,0.85)] flex items-center justify-center select-none"
      style={{
        background: "radial-gradient(ellipse at center, #14070a 0%, #000000 80%)",
      }}
    >
      {/* Top HUD Legend Pill */}
      <div className="absolute top-3 left-3 z-10 flex items-center gap-2 px-3 py-1 rounded-lg bg-black/80 border border-white/10 backdrop-blur-md text-[11px] font-mono text-zinc-300 pointer-events-none">
        <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
        <span>FORCE TOPOLOGY</span>
        <span className="text-red-400 font-bold">2D CORRELATION</span>
      </div>

      {isMounted && width > 0 ? (
        <ForceGraph2D
          ref={graphRef}
          width={width}
          height={460}
          graphData={graphData}
          nodeId="id"
          nodeLabel={(d: any) => `${d.id} (${labelMap[d.group] || "ENTITY"})`}
          nodeCanvasObject={nodeCanvasObject}
          nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, 30, 0, Math.PI * 2);
            ctx.fill();
          }}
          linkCanvasObject={linkCanvasObject}
          linkDirectionalArrowLength={8}
          linkDirectionalArrowColor={() => "#ef4444"}
          linkDirectionalArrowRelPos={0.5}
          enableNodeDrag={true}
          enableZoomInteraction={true}
          enablePanInteraction={true}
          cooldownTicks={120}
          onEngineStop={() => {
            if (graphRef.current) {
              graphRef.current.zoomToFit(400, 30);
            }
          }}
        />
      ) : (
        <GlossySkeleton
          height={460}
          label="SYNTHESIZING FORCE TOPOLOGY GRAPH..."
          sublabel="Computing entity physics, photon links & spring equilibria"
        />
      )}
    </div>
  );
};
