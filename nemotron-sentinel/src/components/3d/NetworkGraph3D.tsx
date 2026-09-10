"use client";

import React, { useRef, useState, useMemo, useEffect, useCallback } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Html } from "@react-three/drei";
import * as THREE from "three";
import { NetworkNode, NetworkLink } from "@/types/network-graph-3d";
import { use3DForceSimulation } from "@/hooks/use3DForceSimulation";
import { ShieldAlert, Globe, Server, Link2, Activity, Zap } from "lucide-react";

interface NetworkGraph3DProps {
  nodes: NetworkNode[];
  links: NetworkLink[];
  onNodeClick?: (node: NetworkNode) => void;
  className?: string;
}

// Color Palette Constants: Strictly Deep Black, Pure White, Crimson Red, Cold Ice Blue & Gold
const THEME_COLORS = {
  black: "#000000",
  white: "#ffffff",
  crimsonRed: "#ef4444",
  darkRed: "#991b1b",
  coldIceBlue: "#38bdf8",
  gold: "#f59e0b",
  coldSlate: "#64748b",
  edgeDefault: "#334155",
  edgeActive: "rgba(239, 68, 68, 0.45)",
};

function getNodeColor(status?: string, group?: string | number): string {
  if (status === "critical" || status === "alert") return THEME_COLORS.crimsonRed;
  if (status === "cold" || group === "dns" || group === "url") return THEME_COLORS.coldIceBlue;
  if (group === "ip") return THEME_COLORS.gold;
  if (status === "normal" || group === "client") return THEME_COLORS.white;
  return THEME_COLORS.white;
}

/**
 * Individual Node with subtle breathing pulse, outer glow halo, and Billboard Text
 */
const GraphNodeMesh: React.FC<{
  node: NetworkNode;
  index: number;
  isSelected: boolean;
  onHover: (node: NetworkNode | null, mouseEvent?: any) => void;
  onClick: (node: NetworkNode) => void;
}> = ({ node, index, isSelected, onHover, onClick }) => {
  const meshRef = useRef<THREE.Mesh>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);

  const baseColor = useMemo(() => getNodeColor(node.status, node.group), [node.status, node.group]);
  const isAlert = node.status === "critical" || node.status === "alert";

  // Subtle breathing / blinking animation on nodes
  useFrame(({ clock }) => {
    const time = clock.getElapsedTime();
    // High-tech subtle pulse: speed is slightly staggered per node
    const pulseFrequency = isAlert ? 3.5 : 2.0;
    const pulseOffset = index * 0.4;
    const pulseScale = 1 + Math.sin(time * pulseFrequency + pulseOffset) * 0.08;

    if (meshRef.current) {
      meshRef.current.scale.setScalar(hovered || isSelected ? 1.35 : pulseScale);
    }
    if (glowRef.current) {
      const glowScale = (hovered ? 1.5 : 1.25) + Math.sin(time * pulseFrequency + pulseOffset) * 0.12;
      glowRef.current.scale.setScalar(glowScale);
      const material = glowRef.current.material as THREE.MeshBasicMaterial;
      if (material) {
        material.opacity = isAlert ? 0.35 + Math.sin(time * pulseFrequency + pulseOffset) * 0.15 : 0.2;
      }
    }
  });

  const nodeRadius = isAlert ? 5.5 : 4.5;
  const position: [number, number, number] = [node.x || 0, node.y || 0, node.z || 0];

  return (
    <group position={position}>
      {/* Outer subtle glow halo */}
      <mesh ref={glowRef}>
        <sphereGeometry args={[nodeRadius * 1.5, 24, 24]} />
        <meshBasicMaterial
          color={baseColor}
          transparent
          opacity={0.25}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>

      {/* Core Node Sphere */}
      <mesh
        ref={meshRef}
        onPointerOver={(e) => {
          e.stopPropagation();
          setHovered(true);
          onHover(node, e);
          document.body.style.cursor = "pointer";
        }}
        onPointerOut={(e) => {
          e.stopPropagation();
          setHovered(false);
          onHover(null);
          document.body.style.cursor = "auto";
        }}
        onClick={(e) => {
          e.stopPropagation();
          onClick(node);
        }}
      >
        <sphereGeometry args={[nodeRadius, 32, 32]} />
        <meshStandardMaterial
          color={baseColor}
          emissive={baseColor}
          emissiveIntensity={isAlert ? 0.6 : 0.3}
          roughness={0.2}
          metalness={0.8}
        />
      </mesh>

      {/* Inner specular ring when selected or alert */}
      {isAlert && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[nodeRadius * 1.7, nodeRadius * 1.9, 32]} />
          <meshBasicMaterial
            color={THEME_COLORS.crimsonRed}
            transparent
            opacity={0.5}
            side={THREE.DoubleSide}
            blending={THREE.AdditiveBlending}
          />
        </mesh>
      )}

      {/* 3D High-Tech Monospace Label & Threat Tag */}
      <Html
        position={[0, nodeRadius + 3.8, 0]}
        center
        distanceFactor={150}
        className="pointer-events-none select-none"
      >
        <div className="flex flex-col items-center gap-0.5 whitespace-nowrap">
          <div className="px-2.5 py-0.5 rounded bg-black/90 border border-white/20 text-white font-mono text-[10px] font-semibold tracking-wider backdrop-blur-md shadow-[0_0_15px_rgba(0,0,0,0.8)]">
            {node.name.length > 24 ? `${node.name.slice(0, 22)}...` : node.name}
          </div>
          {node.metadata?.threatType && (
            <div
              className="px-1.5 py-0.5 text-[8px] font-mono font-bold tracking-wider rounded border uppercase shadow-sm"
              style={{
                color: baseColor,
                backgroundColor: `${baseColor}20`,
                borderColor: `${baseColor}50`,
              }}
            >
              {node.metadata.threatType}
            </div>
          )}
        </div>
      </Html>
    </group>
  );
};

export interface Edge3DProps {
  link: {
    source: NetworkNode;
    target: NetworkNode;
    value?: number;
    label?: string;
    activeFlow?: boolean;
  };
  index: number;
}

/**
 * Volumetric 3D Curved Tube Edge with Interpolated Color Gradient,
 * Emissive Bloom Glow, and Flowing Photons
 */
export const Edge3D: React.FC<Edge3DProps> = ({ link, index }) => {
  const particle1Ref = useRef<THREE.Mesh>(null);
  const particle1GlowRef = useRef<THREE.Mesh>(null);
  const particle2Ref = useRef<THREE.Mesh>(null);
  const particle2GlowRef = useRef<THREE.Mesh>(null);
  const glowMeshRef = useRef<THREE.Mesh>(null);

  // Compute 3D Curved Path, Tube Geometries, and Vertex Color Gradient
  const {
    curve,
    tubeGeometry,
    glowGeometry,
    isAlert,
    isCritical,
    radius,
    particleColor,
  } = useMemo(() => {
    const start = new THREE.Vector3(link.source.x || 0, link.source.y || 0, link.source.z || 0);
    const end = new THREE.Vector3(link.target.x || 0, link.target.y || 0, link.target.z || 0);

    const isCrit = link.source.status === "critical" || link.target.status === "critical";
    const isAlrt = isCrit || link.source.status === "alert" || link.target.status === "alert";

    const sColor = new THREE.Color(getNodeColor(link.source.status, link.source.group));
    const tColor = new THREE.Color(getNodeColor(link.target.status, link.target.group));

    // Midpoint calculation with gentle 3D arc curvature
    const mid = new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5);
    const distance = start.distanceTo(end);
    const dir = new THREE.Vector3().subVectors(end, start).normalize();

    // Normal vector perpendicular to connection axis
    const up = Math.abs(dir.y) > 0.88 ? new THREE.Vector3(1, 0, 0) : new THREE.Vector3(0, 1, 0);
    const normal = new THREE.Vector3().crossVectors(dir, up).normalize();

    // Arc curvature: severity-aware & alternating so links never collide
    const curveMagnitude = Math.min(26, Math.max(7, distance * 0.13));
    const curveSign = index % 2 === 0 ? 1 : -0.85;
    mid.addScaledVector(normal, curveMagnitude * curveSign);
    mid.y += Math.sin(index * 1.7 + 0.4) * 4.5;

    const curvePath = new THREE.CatmullRomCurve3([start, mid, end], false, "catmullrom", 0.35);

    // Tube radius scaled to scene — sleek, refined fiber conduits
    const tubeRadius = isCrit ? 0.48 : isAlrt ? 0.38 : 0.24;
    const tubularSegments = 36;
    const radialSegments = 8;

    // 1. Core 3D Tube Geometry
    const coreGeom = new THREE.TubeGeometry(curvePath, tubularSegments, tubeRadius, radialSegments, false);

    // Smooth vertex color gradient along tube from source to target
    const positionCount = coreGeom.attributes.position.count;
    const colorArray = new Float32Array(positionCount * 3);
    const numRings = tubularSegments + 1;
    const ringVerts = radialSegments + 1;

    for (let r = 0; r < numRings; r++) {
      const t = r / tubularSegments;
      const ringColor = new THREE.Color().copy(sColor).lerp(tColor, t);
      for (let v = 0; v < ringVerts; v++) {
        const idx = (r * ringVerts + v) * 3;
        if (idx + 2 < colorArray.length) {
          colorArray[idx] = ringColor.r;
          colorArray[idx + 1] = ringColor.g;
          colorArray[idx + 2] = ringColor.b;
        }
      }
    }
    coreGeom.setAttribute("color", new THREE.BufferAttribute(colorArray, 3));

    // 2. Outer Volumetric Bloom / Glow Geometry for soft neon aura
    const glowRadius = tubeRadius * 1.65;
    const glowGeom = new THREE.TubeGeometry(curvePath, 28, glowRadius, 8, false);
    const glowColorArray = new Float32Array(glowGeom.attributes.position.count * 3);
    const glowRings = 29;
    const glowRingVerts = 9;

    for (let r = 0; r < glowRings; r++) {
      const t = r / 28;
      const ringColor = new THREE.Color().copy(sColor).lerp(tColor, t);
      for (let v = 0; v < glowRingVerts; v++) {
        const idx = (r * glowRingVerts + v) * 3;
        if (idx + 2 < glowColorArray.length) {
          glowColorArray[idx] = ringColor.r;
          glowColorArray[idx + 1] = ringColor.g;
          glowColorArray[idx + 2] = ringColor.b;
        }
      }
    }
    glowGeom.setAttribute("color", new THREE.BufferAttribute(glowColorArray, 3));

    const pColor = isAlrt ? THEME_COLORS.crimsonRed : THEME_COLORS.coldIceBlue;

    return {
      curve: curvePath,
      tubeGeometry: coreGeom,
      glowGeometry: glowGeom,
      isAlert: isAlrt,
      isCritical: isCrit,
      radius: tubeRadius,
      particleColor: pColor,
    };
  }, [
    link.source.x,
    link.source.y,
    link.source.z,
    link.source.status,
    link.source.group,
    link.target.x,
    link.target.y,
    link.target.z,
    link.target.status,
    link.target.group,
    index,
  ]);

  // Clean up GPU geometries on unmount or re-render
  useEffect(() => {
    return () => {
      tubeGeometry.dispose();
      glowGeometry.dispose();
    };
  }, [tubeGeometry, glowGeometry]);

  // Animate flowing data photons along curve & volumetric bloom pulse
  useFrame(({ clock }) => {
    const time = clock.getElapsedTime();
    const speed = isCritical ? 0.52 + (index % 3) * 0.08 : isAlert ? 0.42 + (index % 3) * 0.06 : 0.28 + (index % 3) * 0.04;

    // Primary flowing photon along 3D CatmullRom curve
    if (particle1Ref.current && link.activeFlow) {
      const t1 = (time * speed + index * 0.2) % 1;
      const p1 = curve.getPointAt(t1);
      particle1Ref.current.position.copy(p1);
      if (particle1GlowRef.current) particle1GlowRef.current.position.copy(p1);
    }

    // Secondary photon on alert/critical high-density edges
    if (particle2Ref.current && isAlert && link.activeFlow) {
      const t2 = (time * speed + index * 0.2 + 0.5) % 1;
      const p2 = curve.getPointAt(t2);
      particle2Ref.current.position.copy(p2);
      if (particle2GlowRef.current) particle2GlowRef.current.position.copy(p2);
    }

    // Soft volumetric glow pulse on outer tube
    if (glowMeshRef.current) {
      const pulseSpeed = isCritical ? 4.5 : isAlert ? 3.0 : 1.8;
      const pulse = Math.sin(time * pulseSpeed + index) * (isAlert ? 0.09 : 0.04);
      const mat = glowMeshRef.current.material as THREE.MeshBasicMaterial;
      if (mat) {
        mat.opacity = (isAlert ? 0.20 : 0.08) + pulse;
      }
    }
  });

  return (
    <group>
      {/* 1. Volumetric 3D Cylinder Core Tube with Lighting & Color Gradient */}
      <mesh geometry={tubeGeometry}>
        <meshStandardMaterial
          vertexColors
          roughness={0.28}
          metalness={0.75}
          emissive={isAlert ? THEME_COLORS.darkRed : new THREE.Color("#081420")}
          emissiveIntensity={isCritical ? 0.85 : isAlert ? 0.55 : 0.2}
          transparent
          opacity={isAlert ? 0.95 : 0.8}
        />
      </mesh>

      {/* 2. Concentric Outer Volumetric Glow Sheath (Bloom aura) */}
      <mesh ref={glowMeshRef} geometry={glowGeometry}>
        <meshBasicMaterial
          vertexColors
          transparent
          opacity={isAlert ? 0.20 : 0.08}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* 3. Flowing Data Photons Along 3D Curve */}
      {link.activeFlow && (
        <>
          {/* Primary Photon Core */}
          <mesh ref={particle1Ref}>
            <sphereGeometry args={[0.7, 16, 16]} />
            <meshBasicMaterial color={particleColor} />
          </mesh>
          {/* Primary Photon Glow Aura */}
          <mesh ref={particle1GlowRef}>
            <sphereGeometry args={[1.4, 16, 16]} />
            <meshBasicMaterial
              color={particleColor}
              transparent
              opacity={0.5}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
            />
          </mesh>

          {/* Secondary Photon Stream on High-Severity / Threat Links */}
          {isAlert && (
            <>
              <mesh ref={particle2Ref}>
                <sphereGeometry args={[0.55, 16, 16]} />
                <meshBasicMaterial color={THEME_COLORS.crimsonRed} />
              </mesh>
              <mesh ref={particle2GlowRef}>
                <sphereGeometry args={[1.1, 16, 16]} />
                <meshBasicMaterial
                  color={THEME_COLORS.crimsonRed}
                  transparent
                  opacity={0.4}
                  blending={THREE.AdditiveBlending}
                  depthWrite={false}
                />
              </mesh>
            </>
          )}
        </>
      )}
    </group>
  );
};

// Export GraphEdge as alias for seamless drop-in compatibility
export const GraphEdge = Edge3D;

/**
 * 3D Scene Inside Canvas
 */
const GraphScene: React.FC<{
  nodes: NetworkNode[];
  links: NetworkLink[];
  onNodeClick: (node: NetworkNode) => void;
  hoveredNode: NetworkNode | null;
  setHoveredNode: (node: NetworkNode | null) => void;
  selectedNode: NetworkNode | null;
  isAutoRotating: boolean;
  onInteractionStart: () => void;
  onInteractionEnd: () => void;
}> = ({
  nodes,
  links,
  onNodeClick,
  hoveredNode,
  setHoveredNode,
  selectedNode,
  isAutoRotating,
  onInteractionStart,
  onInteractionEnd,
}) => {
  const { nodes: simNodes, links: simLinks } = use3DForceSimulation(nodes, links);

  return (
    <>
      {/* Background void fog for infinite depth */}
      <fog attach="fog" args={[THEME_COLORS.black, 180, 750]} />

      {/* Cyber Enterprise Lighting */}
      <ambientLight intensity={0.4} />
      <directionalLight position={[100, 150, 100]} intensity={1.2} color={THEME_COLORS.white} />
      <directionalLight position={[-100, -100, -100]} intensity={0.5} color={THEME_COLORS.coldIceBlue} />
      <pointLight position={[0, 0, 0]} intensity={1.5} distance={300} color={THEME_COLORS.crimsonRed} />

      {/* Render Volumetric 3D Curved Tube Edges with Gradient Glow & Photons */}
      {simLinks.map((link, idx) => (
        <Edge3D key={`edge-${idx}`} link={link} index={idx} />
      ))}

      {/* Render 3D Nodes with breathing glow & Billboard text */}
      {simNodes.map((node, idx) => (
        <GraphNodeMesh
          key={`node-${node.id}`}
          node={node}
          index={idx}
          isSelected={selectedNode?.id === node.id}
          onHover={(n) => setHoveredNode(n)}
          onClick={onNodeClick}
        />
      ))}

      {/* Smooth Enterprise OrbitControls (Damped rotation, pan, zoom with auto-rotate & mouse interrupt) */}
      <OrbitControls
        makeDefault
        enableDamping
        dampingFactor={0.06}
        rotateSpeed={0.8}
        zoomSpeed={1.0}
        panSpeed={0.8}
        minDistance={50}
        maxDistance={650}
        autoRotate={isAutoRotating}
        autoRotateSpeed={0.35} // Very slow, majestic, cinematic pace
        onStart={onInteractionStart}
        onEnd={onInteractionEnd}
      />
    </>
  );
};

/**
 * Main Production-Ready 3D Network Graph Component
 */
export const NetworkGraph3D: React.FC<NetworkGraph3DProps> = ({
  nodes,
  links,
  onNodeClick,
  className = "",
}) => {
  const [hoveredNode, setHoveredNode] = useState<NetworkNode | null>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [isAutoRotating, setIsAutoRotating] = useState(true);
  const resumeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Pause auto-rotation when user hovers or selects a node
  useEffect(() => {
    if (hoveredNode || selectedNode) {
      if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
      setIsAutoRotating(false);
    } else {
      if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
      resumeTimerRef.current = setTimeout(() => {
        setIsAutoRotating(true);
      }, 2500);
    }
  }, [hoveredNode, selectedNode]);

  // User mouse drag / pan / zoom interaction handlers
  const handleInteractionStart = useCallback(() => {
    if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
    setIsAutoRotating(false);
  }, []);

  const handleInteractionEnd = useCallback(() => {
    if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
    resumeTimerRef.current = setTimeout(() => {
      setIsAutoRotating(true);
    }, 3000); // 3 seconds of inactivity before smoothly resuming
  }, []);

  useEffect(() => {
    return () => {
      if (resumeTimerRef.current) clearTimeout(resumeTimerRef.current);
    };
  }, []);

  const handleNodeSelect = (node: NetworkNode) => {
    setSelectedNode((prev) => (prev?.id === node.id ? null : node));
    if (onNodeClick) onNodeClick(node);
  };

  return (
    <div
      onPointerDown={handleInteractionStart}
      onPointerUp={handleInteractionEnd}
      onWheel={() => {
        handleInteractionStart();
        handleInteractionEnd();
      }}
      className={`relative w-full h-[520px] rounded-2xl overflow-hidden bg-black border border-white/10 select-none shadow-[0_0_50px_rgba(0,0,0,0.9)] ${className}`}
    >
      {/* Tactical Engineering Graph Paper White Dotted Grid Backdrop */}
      <div
        className="absolute inset-0 pointer-events-none z-0"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='144' height='144' viewBox='0 0 144 144' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M 144 0 L 0 0 0 144' fill='none' stroke='rgba(255,255,255,0.22)' stroke-width='1' stroke-dasharray='2,2'/%3E%3Cpath d='M 36 0 L 36 144 M 72 0 L 72 144 M 108 0 L 108 144 M 0 36 L 144 36 M 0 72 L 144 72 M 0 108 L 144 108' fill='none' stroke='rgba(255,255,255,0.11)' stroke-width='1' stroke-dasharray='1,3'/%3E%3Ccircle cx='0' cy='0' r='1.8' fill='rgba(255,255,255,0.45)'/%3E%3Ccircle cx='72' cy='72' r='1.1' fill='rgba(255,255,255,0.22)'/%3E%3C/svg%3E")`,
          backgroundSize: "144px 144px",
          maskImage: "radial-gradient(ellipse 75% 70% at 50% 50%, rgba(0, 0, 0, 0.95) 20%, rgba(0, 0, 0, 0.4) 65%, rgba(0, 0, 0, 0) 100%)",
          WebkitMaskImage: "radial-gradient(ellipse 75% 70% at 50% 50%, rgba(0, 0, 0, 0.95) 20%, rgba(0, 0, 0, 0.4) 65%, rgba(0, 0, 0, 0) 100%)",
        }}
      />

      {/* Tactical Blueprint Corner Crosshairs */}
      <div className="absolute top-3 left-3 w-3 h-3 border-t border-l border-white/20 pointer-events-none z-10" />
      <div className="absolute top-3 right-3 w-3 h-3 border-t border-r border-white/20 pointer-events-none z-10" />
      <div className="absolute bottom-3 left-3 w-3 h-3 border-b border-l border-white/20 pointer-events-none z-10" />
      <div className="absolute bottom-3 right-3 w-3 h-3 border-b border-r border-white/20 pointer-events-none z-10" />

      {/* Top HUD Status Bar */}
      <div className="absolute top-3.5 left-4 z-10 flex items-center gap-2.5 px-3.5 py-1.5 rounded-xl bg-black/80 border border-white/15 backdrop-blur-xl text-xs font-mono pointer-events-none">
        <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
        <span className="text-zinc-300 font-semibold">3D TOPOLOGY ARCHITECTURE</span>
        <span className="text-zinc-600">|</span>
        <span className="text-red-400 font-bold">R3F ENGINE</span>
        <span className="text-zinc-600">|</span>
        <span className={`w-1.5 h-1.5 rounded-full ${isAutoRotating ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
        <span className="text-[10px] text-zinc-300">
          {isAutoRotating ? "AUTO-ORBIT" : "MANUAL CONTROL"}
        </span>
      </div>

      <div className="absolute top-3.5 right-4 z-10 hidden sm:flex items-center gap-3 px-3 py-1.5 rounded-xl bg-black/80 border border-white/10 backdrop-blur-xl text-[11px] font-mono text-zinc-400 pointer-events-none">
        <span>Rotate: Left Click</span>
        <span>•</span>
        <span>Pan: Right Click</span>
        <span>•</span>
        <span>Zoom: Scroll</span>
      </div>

      {/* R3F WebGL Canvas */}
      <Canvas
        camera={{ position: [0, 60, 260], fov: 48 }}
        gl={{
          antialias: true,
          alpha: true,
          powerPreference: "high-performance",
        }}
        dpr={[1, 2]}
      >
        <React.Suspense fallback={null}>
          <GraphScene
            nodes={nodes}
            links={links}
            onNodeClick={handleNodeSelect}
            hoveredNode={hoveredNode}
            setHoveredNode={setHoveredNode}
            selectedNode={selectedNode}
            isAutoRotating={isAutoRotating}
            onInteractionStart={handleInteractionStart}
            onInteractionEnd={handleInteractionEnd}
          />
        </React.Suspense>
      </Canvas>

      {/* Sleek HTML Telemetry Hover Tooltip */}
      {hoveredNode && (
        <div
          className="absolute bottom-5 left-5 z-20 max-w-sm w-full p-4 rounded-xl bg-black/90 backdrop-blur-2xl border border-red-500/40 shadow-[0_0_35px_rgba(239,68,68,0.25)] text-white font-mono pointer-events-none transition-all duration-200 animate-in fade-in zoom-in-95"
        >
          {/* Header */}
          <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-white/10">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30">
                {hoveredNode.group === "email" ? (
                  <Activity className="w-4 h-4" />
                ) : hoveredNode.group === "domain" ? (
                  <Globe className="w-4 h-4" />
                ) : hoveredNode.group === "ip" ? (
                  <Server className="w-4 h-4" />
                ) : (
                  <Link2 className="w-4 h-4" />
                )}
              </div>
              <div>
                <h4 className="font-bold text-sm text-white tracking-tight truncate max-w-[200px]">
                  {hoveredNode.name}
                </h4>
                <span className="text-[10px] text-zinc-400 uppercase tracking-wider">
                  ENTITY: {String(hoveredNode.group).toUpperCase()}
                </span>
              </div>
            </div>

            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                hoveredNode.status === "critical" || hoveredNode.status === "alert"
                  ? "bg-red-500/20 text-red-400 border-red-500/40"
                  : "bg-cyan-500/20 text-cyan-400 border-cyan-500/40"
              }`}
            >
              {hoveredNode.status ? hoveredNode.status.toUpperCase() : "ACTIVE"}
            </span>
          </div>

          {/* Telemetry Metrics */}
          <div className="grid grid-cols-2 gap-2 text-xs mb-2">
            <div className="p-2 rounded-lg bg-white/[0.03] border border-white/5">
              <span className="text-zinc-500 text-[10px] block">RISK SCORE</span>
              <span className="font-bold text-sm text-red-400">
                {hoveredNode.metadata?.riskScore ?? "88.5"} / 100
              </span>
            </div>

            <div className="p-2 rounded-lg bg-white/[0.03] border border-white/5">
              <span className="text-zinc-500 text-[10px] block">PROTOCOL</span>
              <span className="font-bold text-sm text-zinc-200 truncate block">
                {hoveredNode.metadata?.protocol ?? "TCP/TLS"}
              </span>
            </div>
          </div>

          {/* Description */}
          {hoveredNode.metadata?.description && (
            <p className="text-[11px] text-zinc-300/80 leading-relaxed border-t border-white/5 pt-2">
              {hoveredNode.metadata.description}
            </p>
          )}

          {hoveredNode.metadata?.coordinates && (
            <div className="mt-2 text-[10px] text-zinc-500 flex items-center justify-between">
              <span>LAT/LNG:</span>
              <span className="text-cyan-400 font-mono">{hoveredNode.metadata.coordinates}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default NetworkGraph3D;
