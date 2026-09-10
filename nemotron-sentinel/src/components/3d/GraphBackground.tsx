"use client";

import React, { useRef, useMemo, useEffect, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";

/**
 * ShootingStar: Occasional realistic meteor streak gliding across the night sky
 */
const ShootingStar: React.FC<{ isTabVisible: boolean }> = ({ isTabVisible }) => {
  const lineRef = useRef<THREE.Line>(null);
  const meteorState = useRef({
    active: false,
    progress: 0,
    speed: 0.8,
    start: new THREE.Vector3(),
    end: new THREE.Vector3(),
    nextSpawnTime: 3.5,
  });

  const { lineGeo, lineMat } = useMemo(() => {
    const geo = new THREE.BufferGeometry();
    const positions = new Float32Array(6); // 2 vertices: head and tail
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));

    const mat = new THREE.LineBasicMaterial({
      color: new THREE.Color("#ffffff"),
      transparent: true,
      opacity: 0,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    return { lineGeo: geo, lineMat: mat };
  }, []);

  useEffect(() => {
    return () => {
      lineGeo.dispose();
      lineMat.dispose();
    };
  }, [lineGeo, lineMat]);

  useFrame(({ clock }) => {
    if (!isTabVisible || !lineRef.current) return;
    const time = clock.getElapsedTime();
    const state = meteorState.current;

    // Trigger meteor spawn
    if (!state.active && time > state.nextSpawnTime) {
      state.active = true;
      state.progress = 0;
      state.speed = 1.2 + Math.random() * 0.8;

      // Spawn near upper bounds, trajectory down-right
      const startX = -180 + Math.random() * 160;
      const startY = 80 + Math.random() * 60;
      const startZ = 20 + Math.random() * 40;
      state.start.set(startX, startY, startZ);

      const length = 120 + Math.random() * 80;
      state.end.set(startX + length, startY - length * 0.65, startZ - 20);
    }

    if (state.active) {
      state.progress += 0.022 * state.speed;

      if (state.progress >= 1.0) {
        state.active = false;
        lineMat.opacity = 0;
        state.nextSpawnTime = time + 5.0 + Math.random() * 6.0; // Next meteor in 5-11s
        return;
      }

      // Interpolate head and tail
      const t = state.progress;
      const tailT = Math.max(0, t - 0.22);

      const headX = state.start.x + (state.end.x - state.start.x) * t;
      const headY = state.start.y + (state.end.y - state.start.y) * t;
      const headZ = state.start.z + (state.end.z - state.start.z) * t;

      const tailX = state.start.x + (state.end.x - state.start.x) * tailT;
      const tailY = state.start.y + (state.end.y - state.start.y) * tailT;
      const tailZ = state.start.z + (state.end.z - state.start.z) * tailT;

      const posAttr = lineGeo.attributes.position as THREE.BufferAttribute;
      posAttr.setXYZ(0, tailX, tailY, tailZ);
      posAttr.setXYZ(1, headX, headY, headZ);
      posAttr.needsUpdate = true;

      // Parabolic alpha curve: quick flash in, slow trail dissolve
      lineMat.opacity = Math.sin(t * Math.PI) * 0.85;
    }
  });

  return <primitive object={new THREE.Line(lineGeo, lineMat)} ref={lineRef} />;
};

/**
 * Subtle Constellation Mesh: Delicate starlight strands interconnecting celestial nodes
 */
const SubtleConstellation: React.FC<{ isTabVisible: boolean }> = ({ isTabVisible }) => {
  const groupRef = useRef<THREE.Group>(null);

  const { pointsGeo, linesGeo } = useMemo(() => {
    const nodeCount = 42;
    const nodes: THREE.Vector3[] = [];
    const brandColors = [
      new THREE.Color("#38bdf8"), // Ice blue accent
      new THREE.Color("#ef4444"), // Crimson threat star
      new THREE.Color("#ffffff"), // Pure white
      new THREE.Color("#67e8f9"), // Cyan starlight
    ];

    for (let i = 0; i < nodeCount; i++) {
      const radius = 60 + Math.random() * 95;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      nodes.push(
        new THREE.Vector3(
          radius * Math.sin(phi) * Math.cos(theta) * 1.3,
          radius * Math.sin(phi) * Math.sin(theta) * 0.75,
          radius * Math.cos(phi) * 0.8
        )
      );
    }

    const pairs: [number, number][] = [];
    for (let i = 0; i < nodeCount; i++) {
      for (let j = i + 1; j < nodeCount; j++) {
        if (nodes[i].distanceTo(nodes[j]) < 48) {
          pairs.push([i, j]);
        }
      }
    }
    const cappedPairs = pairs.slice(0, 50);

    const pGeo = new THREE.BufferGeometry();
    const pPos = new Float32Array(nodeCount * 3);
    const pCol = new Float32Array(nodeCount * 3);
    nodes.forEach((n, i) => {
      pPos[i * 3] = n.x;
      pPos[i * 3 + 1] = n.y;
      pPos[i * 3 + 2] = n.z;
      const col = brandColors[i % brandColors.length];
      pCol[i * 3] = col.r;
      pCol[i * 3 + 1] = col.g;
      pCol[i * 3 + 2] = col.b;
    });
    pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
    pGeo.setAttribute("color", new THREE.BufferAttribute(pCol, 3));

    const lGeo = new THREE.BufferGeometry();
    const lPos = new Float32Array(cappedPairs.length * 2 * 3);
    const lCol = new Float32Array(cappedPairs.length * 2 * 3);
    cappedPairs.forEach(([i, j], idx) => {
      const b = idx * 6;
      lPos[b] = nodes[i].x;
      lPos[b + 1] = nodes[i].y;
      lPos[b + 2] = nodes[i].z;
      lPos[b + 3] = nodes[j].x;
      lPos[b + 4] = nodes[j].y;
      lPos[b + 5] = nodes[j].z;

      const col1 = brandColors[i % brandColors.length];
      const col2 = brandColors[j % brandColors.length];
      lCol[b] = col1.r;
      lCol[b + 1] = col1.g;
      lCol[b + 2] = col1.b;
      lCol[b + 3] = col2.r;
      lCol[b + 4] = col2.g;
      lCol[b + 5] = col2.b;
    });
    lGeo.setAttribute("position", new THREE.BufferAttribute(lPos, 3));
    lGeo.setAttribute("color", new THREE.BufferAttribute(lCol, 3));

    return { pointsGeo: pGeo, linesGeo: lGeo };
  }, []);

  useEffect(() => {
    return () => {
      pointsGeo.dispose();
      linesGeo.dispose();
    };
  }, [pointsGeo, linesGeo]);

  useFrame(({ clock }) => {
    if (!isTabVisible || !groupRef.current) return;
    const time = clock.getElapsedTime();
    groupRef.current.rotation.y = time * 0.012;
    groupRef.current.rotation.x = Math.sin(time * 0.02) * 0.02;
  });

  return (
    <group ref={groupRef}>
      <points geometry={pointsGeo}>
        <pointsMaterial
          size={3.2}
          vertexColors
          transparent
          opacity={0.45}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
          sizeAttenuation
        />
      </points>
      <lineSegments geometry={linesGeo}>
        <lineBasicMaterial
          vertexColors
          transparent
          opacity={0.09}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </lineSegments>
    </group>
  );
};

/**
 * Standalone Ambient 3D Cyber Constellation & Meteor Canvas
 */
export const GraphBackground: React.FC<{ className?: string }> = ({ className = "" }) => {
  const [isMounted, setIsMounted] = useState(false);
  const [isTabVisible, setIsTabVisible] = useState(true);

  useEffect(() => {
    setIsMounted(true);
    const handleVisibilityChange = () => {
      setIsTabVisible(!document.hidden);
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);

  if (!isMounted) return null;

  return (
    <div
      className={`fixed inset-0 pointer-events-none z-0 overflow-hidden select-none ${className}`}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 0,
        pointerEvents: "none",
      }}
      aria-hidden="true"
    >
      <Canvas
        camera={{ position: [0, 0, 160], fov: 54 }}
        gl={{
          antialias: true,
          alpha: true,
          powerPreference: "low-power",
        }}
        dpr={[1, 1.5]}
        style={{ pointerEvents: "none" }}
      >
        <fog attach="fog" args={["#000000", 90, 320]} />
        <ShootingStar isTabVisible={isTabVisible} />
        <SubtleConstellation isTabVisible={isTabVisible} />
      </Canvas>
    </div>
  );
};

export default GraphBackground;
