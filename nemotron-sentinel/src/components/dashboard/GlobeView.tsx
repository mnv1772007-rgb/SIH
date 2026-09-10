"use client";

import React, { useRef, useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { GlossySkeleton } from "@/components/ui/GlossySkeleton";
import { useResizeObserver } from "@/hooks/useResizeObserver";
import { MapPin, Navigation } from "lucide-react";

// Dynamic import with SSR disabled and GlossySkeleton fallback
const GlobeComponent = dynamic(() => import("react-globe.gl").then((mod) => mod.default), {
  ssr: false,
  loading: () => (
    <GlossySkeleton
      height={460}
      label="INITIALIZING 3D GEOLOCATION SPHERE..."
      sublabel="Streaming Earth nighttime textures & orbital arcs"
    />
  ),
}) as any;

interface GlobeViewProps {
  originLat: number;
  originLng: number;
  destinationLat: number;
  destinationLng: number;
  originLabel?: string;
  destinationLabel?: string;
  arcColor?: string;
}

export const GlobeView: React.FC<GlobeViewProps> = ({
  originLat,
  originLng,
  destinationLat,
  destinationLng,
  originLabel = "Client (US-West)",
  destinationLabel = "Threat Origin",
  arcColor = "#ef4444",
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const globeRef = useRef<any>(null);
  const { width } = useResizeObserver(containerRef, { width: 400, height: 460 });
  const [isMounted, setIsMounted] = useState(false);
  const [isAutoRotating, setIsAutoRotating] = useState(true);
  const resumeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  // Professional, slow globe auto-rotation with seamless mouse interrupt handling
  useEffect(() => {
    if (!isMounted) return;

    let isCleanedUp = false;
    let controlsInstance: any = null;

    const setupControls = () => {
      if (isCleanedUp) return;
      if (!globeRef.current) {
        setTimeout(setupControls, 100);
        return;
      }

      const controls = typeof globeRef.current.controls === "function" ? globeRef.current.controls() : null;
      if (!controls) {
        setTimeout(setupControls, 100);
        return;
      }

      controlsInstance = controls;
      controls.autoRotate = true;
      controls.autoRotateSpeed = 0.35; // Very slow, majestic, cinematic pace
      controls.enableDamping = true;
      controls.dampingFactor = 0.08;

      const handleStart = () => {
        if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
        controls.autoRotate = false;
        setIsAutoRotating(false);
      };

      const handleEnd = () => {
        if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
        resumeTimerRef.current = setTimeout(() => {
          if (!isCleanedUp && controlsInstance) {
            controlsInstance.autoRotate = true;
            setIsAutoRotating(true);
          }
        }, 3000); // 3s idle cooldown before smoothly resuming
      };

      controls.addEventListener("start", handleStart);
      controls.addEventListener("end", handleEnd);

      return () => {
        controls.removeEventListener("start", handleStart);
        controls.removeEventListener("end", handleEnd);
      };
    };

    const cleanup = setupControls();

    return () => {
      isCleanedUp = true;
      if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
      if (typeof cleanup === "function") cleanup();
      if (controlsInstance) controlsInstance.autoRotate = false;
    };
  }, [isMounted]);

  // Handle container-level pointer/wheel interactions
  const handlePointerDown = () => {
    if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
    if (globeRef.current?.controls) {
      const controls = globeRef.current.controls();
      if (controls) controls.autoRotate = false;
    }
    setIsAutoRotating(false);
  };

  const handlePointerUp = () => {
    if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
    resumeTimerRef.current = setTimeout(() => {
      if (globeRef.current?.controls) {
        const controls = globeRef.current.controls();
        if (controls) controls.autoRotate = true;
      }
      setIsAutoRotating(true);
    }, 3000);
  };

  const handleWheel = () => {
    if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
    if (globeRef.current?.controls) {
      const controls = globeRef.current.controls();
      if (controls) controls.autoRotate = false;
    }
    setIsAutoRotating(false);
    resumeTimerRef.current = setTimeout(() => {
      if (globeRef.current?.controls) {
        const controls = globeRef.current.controls();
        if (controls) controls.autoRotate = true;
      }
      setIsAutoRotating(true);
    }, 3000);
  };

  // Points of interest on globe (Cold Ice Client vs Crimson Threat Origin)
  const markersData = [
    {
      lat: originLat,
      lng: originLng,
      size: 0.65,
      color: "#38bdf8",
      label: originLabel,
    },
    {
      lat: destinationLat,
      lng: destinationLng,
      size: 0.95,
      color: "#ef4444",
      label: destinationLabel,
    },
  ];

  const arcsData = [
    {
      startLat: originLat,
      startLng: originLng,
      endLat: destinationLat,
      endLng: destinationLng,
      color: ["#38bdf8", arcColor],
    },
  ];

  return (
    <div
      ref={containerRef}
      onPointerDown={handlePointerDown}
      onPointerUp={handlePointerUp}
      onWheel={handleWheel}
      className="relative w-full h-[460px] rounded-2xl overflow-hidden bg-black/70 backdrop-blur-xl border border-white/10 shadow-[0_0_40px_rgba(0,0,0,0.85)] flex items-center justify-center select-none"
      style={{
        background: "radial-gradient(ellipse at center, #18090d 0%, #000000 80%)",
      }}
    >
      {/* Top telemetry HUD tag */}
      <div className="absolute top-3 left-3 z-10 flex items-center gap-2 px-3 py-1 rounded-lg bg-black/80 border border-white/10 backdrop-blur-md text-[11px] font-mono text-zinc-300 pointer-events-none">
        <Navigation className="w-3 h-3 text-red-400" />
        <span>ORBITAL TELEMETRY</span>
        <span className="text-red-400 font-bold">ARC-GEO</span>
        <span className="text-zinc-600">|</span>
        <span className={`w-1.5 h-1.5 rounded-full ${isAutoRotating ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
        <span className="text-[10px] text-zinc-400">{isAutoRotating ? "AUTO-ORBIT" : "MANUAL"}</span>
      </div>

      <div className="absolute top-3 right-3 z-10 flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-red-500/15 border border-red-500/30 backdrop-blur-md text-[11px] font-mono text-red-300 pointer-events-none">
        <MapPin className="w-3 h-3 text-red-400" />
        <span className="truncate max-w-[130px]">{destinationLabel}</span>
      </div>

      {isMounted && width > 0 ? (
        <GlobeComponent
          ref={globeRef}
          width={width}
          height={460}
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
          backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
          showGraticules={true}
          showAtmosphere={true}
          atmosphereColor="#ef4444"
          atmosphereAltitude={0.16}
          pointsData={markersData}
          pointLat="lat"
          pointLng="lng"
          pointColor="color"
          pointRadius="size"
          pointAltitude={0.02}
          arcsData={arcsData}
          arcStartLat="startLat"
          arcStartLng="startLng"
          arcEndLat="endLat"
          arcEndLng="endLng"
          arcColor="color"
          arcAltitude={0.35}
          arcStroke={1.3}
          arcDashLength={0.45}
          arcDashGap={0.2}
          arcDashAnimateTime={2000}
          arcCircularResolution={24}
          pointOfView={{ lat: 35, lng: 20, altitude: 2.3 }}
          animateIn={true}
        />
      ) : (
        <GlossySkeleton
          height={460}
          label="INITIALIZING 3D GEOLOCATION SPHERE..."
          sublabel="Streaming Earth nighttime textures & orbital arcs"
        />
      )}
    </div>
  );
};
