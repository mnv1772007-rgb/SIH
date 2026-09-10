"use client";

import React, { useRef, useEffect, useMemo, useState } from "react";

export interface StarfieldProps {
  /**
   * Total number of scattered stars to generate (150-300 recommended).
   * @default 220
   */
  starCount?: number;
  /**
   * Whether to layer the subtle engineering graph-paper grid beneath the stars.
   * @default false
   */
  showGrid?: boolean;
  /**
   * Optional custom CSS class name.
   */
  className?: string;
}

interface Star {
  // Normalized viewport coordinates [0, 1] so resize does not re-randomize positions
  xRatio: number;
  yRatio: number;
  // Radius in pixels (1px - 3px)
  radius: number;
  // Base opacity (0.2 - 0.9)
  baseOpacity: number;
  // Current opacity computed each frame
  currentOpacity: number;
  // Hex / RGBA color string (pure white to light blue-white)
  color: string;
  // Depth layer: 0 = Far (slow/static), 1 = Mid, 2 = Near (more parallax drift)
  layer: 0 | 1 | 2;
  // Parallax responsiveness factor
  parallaxFactor: number;
  // Twinkle configuration
  isTwinkling: boolean;
  twinkleSpeed: number;
  twinklePhase: number;
}

/**
 * Standalone Starfield Background Component
 * Renders a lightweight 2D canvas with 150-300 randomized stars, multi-depth parallax,
 * subtle twinkling animation, and tab visibility pausing.
 */
export const Starfield: React.FC<StarfieldProps> = ({
  starCount = 220,
  showGrid = false,
  className = "",
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [isMounted, setIsMounted] = useState(false);

  // Mouse coordinates with smoothing for parallax
  const mouseTargetRef = useRef({ x: 0, y: 0 });
  const mouseCurrentRef = useRef({ x: 0, y: 0 });
  const scrollYRef = useRef(0);

  // Tab visibility state to pause animation loop
  const isTabVisibleRef = useRef(true);
  const animationFrameIdRef = useRef<number | null>(null);

  // Generate deterministic randomized stars ONCE on mount
  const stars = useMemo<Star[]>(() => {
    const starList: Star[] = [];
    const colorPalette = [
      "#ffffff", // Pure white
      "#ffffff", // Pure white
      "#f8fafc", // Crisp cold white
      "#f0f9ff", // Ice white
      "#e0f2fe", // Diamond sky white
      "#dce8ff", // Light blue-white
      "#bae6fd", // Subtle cyan starlight
    ];

    for (let i = 0; i < starCount; i++) {
      const rand = Math.random();
      let layer: 0 | 1 | 2;
      let radius: number;
      let baseOpacity: number;
      let parallaxFactor: number;

      // Depth distribution:
      // 55% Far (small, faint, static)
      // 32% Mid (medium, gentle drift)
      // 13% Near (larger, brighter, noticeable drift)
      if (rand < 0.55) {
        layer = 0;
        radius = 0.8 + Math.random() * 0.6; // ~0.8px - 1.4px
        baseOpacity = 0.22 + Math.random() * 0.28; // 0.22 - 0.50
        parallaxFactor = 0.008;
      } else if (rand < 0.87) {
        layer = 1;
        radius = 1.4 + Math.random() * 0.8; // ~1.4px - 2.2px
        baseOpacity = 0.45 + Math.random() * 0.28; // 0.45 - 0.73
        parallaxFactor = 0.024;
      } else {
        layer = 2;
        radius = 2.2 + Math.random() * 0.8; // ~2.2px - 3.0px
        baseOpacity = 0.70 + Math.random() * 0.25; // 0.70 - 0.95
        parallaxFactor = 0.048;
      }

      // ~18% of stars twinkle subtly
      const isTwinkling = Math.random() < 0.18;
      const twinkleSpeed = 0.8 + Math.random() * 1.6; // 3s - 6s period
      const twinklePhase = Math.random() * Math.PI * 2;
      const color = colorPalette[Math.floor(Math.random() * colorPalette.length)];

      starList.push({
        xRatio: Math.random(),
        yRatio: Math.random(),
        radius,
        baseOpacity,
        currentOpacity: baseOpacity,
        color,
        layer,
        parallaxFactor,
        isTwinkling,
        twinkleSpeed,
        twinklePhase,
      });
    }

    return starList;
  }, [starCount]);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  useEffect(() => {
    if (!isMounted) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let dpr = 1;

    // Resize canvas respecting devicePixelRatio
    const handleResize = () => {
      if (!canvas) return;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;

      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    handleResize();
    window.addEventListener("resize", handleResize, { passive: true });

    // Track mouse position relative to center [-1, 1]
    const handleMouseMove = (e: MouseEvent) => {
      mouseTargetRef.current = {
        x: (e.clientX / width - 0.5) * 2,
        y: (e.clientY / height - 0.5) * 2,
      };
    };
    window.addEventListener("mousemove", handleMouseMove, { passive: true });

    // Track window scroll
    const handleScroll = () => {
      scrollYRef.current = window.scrollY || 0;
    };
    window.addEventListener("scroll", handleScroll, { passive: true });

    // Tab visibility handling: pause render loop when tab is hidden
    const handleVisibilityChange = () => {
      isTabVisibleRef.current = !document.hidden;
      if (isTabVisibleRef.current && !animationFrameIdRef.current) {
        lastTime = performance.now();
        animationFrameIdRef.current = requestAnimationFrame(render);
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    let lastTime = performance.now();

    // 60fps render loop
    const render = (time: number) => {
      if (!isTabVisibleRef.current) {
        animationFrameIdRef.current = null;
        return;
      }

      const delta = (time - lastTime) / 1000;
      lastTime = time;
      const elapsedSeconds = time / 1000;

      // Smooth mouse interpolation (spring dampening)
      mouseCurrentRef.current.x +=
        (mouseTargetRef.current.x - mouseCurrentRef.current.x) * 0.04;
      mouseCurrentRef.current.y +=
        (mouseTargetRef.current.y - mouseCurrentRef.current.y) * 0.04;

      const mouseX = mouseCurrentRef.current.x;
      const mouseY = mouseCurrentRef.current.y;
      const scrollYOffset = scrollYRef.current * 0.02;

      // Clear canvas
      ctx.clearRect(0, 0, width, height);

      // Render stars with depth and twinkle
      for (let i = 0; i < stars.length; i++) {
        const star = stars[i];

        // Parallax offset: mouse drift + vertical scroll drift
        const offsetX = -mouseX * star.parallaxFactor * 45;
        const offsetY = -mouseY * star.parallaxFactor * 35 - scrollYOffset * star.parallaxFactor;

        // Wrapped coordinates so stars never clip or disappear offscreen
        let x = (star.xRatio * width + offsetX) % width;
        if (x < 0) x += width;
        let y = (star.yRatio * height + offsetY) % height;
        if (y < 0) y += height;

        // Twinkle calculation: opacity oscillation between 0.3 * base and 1.0
        let alpha = star.baseOpacity;
        if (star.isTwinkling) {
          const wave = Math.sin(elapsedSeconds * star.twinkleSpeed + star.twinklePhase);
          // Non-linear sparkle curve
          const twinkleIntensity = 0.35 + 0.65 * (0.5 + 0.5 * wave);
          alpha = Math.min(1.0, star.baseOpacity * twinkleIntensity * 1.3);
        }

        ctx.save();
        ctx.globalAlpha = Math.max(0.1, Math.min(alpha, 1.0));

        // Soft halo glow for near/prominent stars
        if (star.layer === 2) {
          const glowRadius = star.radius * 2.2;
          const gradient = ctx.createRadialGradient(x, y, 0, x, y, glowRadius);
          gradient.addColorStop(0, star.color);
          gradient.addColorStop(0.3, "rgba(220, 232, 255, 0.4)");
          gradient.addColorStop(1, "rgba(220, 232, 255, 0)");
          ctx.fillStyle = gradient;
          ctx.beginPath();
          ctx.arc(x, y, glowRadius, 0, Math.PI * 2);
          ctx.fill();
        }

        // Star core
        ctx.fillStyle = star.color;
        ctx.beginPath();
        ctx.arc(x, y, star.radius, 0, Math.PI * 2);
        ctx.fill();

        ctx.restore();
      }

      animationFrameIdRef.current = requestAnimationFrame(render);
    };

    animationFrameIdRef.current = requestAnimationFrame(render);

    return () => {
      if (animationFrameIdRef.current) {
        cancelAnimationFrame(animationFrameIdRef.current);
      }
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("scroll", handleScroll);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [isMounted, stars]);

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
      {/* Optional Underlying Engineering Graph-Paper Grid */}
      {showGrid && (
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: `
              radial-gradient(circle, rgba(255, 255, 255, 0.14) 1px, transparent 1px)
            `,
            backgroundSize: "24px 24px",
            opacity: 0.7,
          }}
        />
      )}

      {/* 2D Canvas Starfield with Screen Blending */}
      <canvas
        ref={canvasRef}
        className="w-full h-full block"
        style={{
          mixBlendMode: "screen",
          opacity: 0.92,
        }}
      />
    </div>
  );
};

export default Starfield;
