"use client";

import React, { useEffect, useState } from "react";

export interface LightSweepProps {
  /**
   * Primary sweep cycle duration in seconds (active sweep + pause).
   * @default 8.5
   */
  cycleDuration?: number;
  /**
   * Peak opacity for the primary light band.
   * @default 0.35
   */
  peakOpacity?: number;
  /**
   * Whether to enable the primary white radiant light flash (Left to Right).
   * @default false (Removed per user request)
   */
  enablePrimarySweep?: boolean;
  /**
   * Whether to enable the secondary deeper ambient sweep band.
   * @default true
   */
  enableSecondarySweep?: boolean;
  /**
   * Whether to enable the foreground specular sheen layer across UI cards.
   * @default false
   */
  enableOverlaySheen?: boolean;
  /**
   * Optional custom CSS class name.
   */
  className?: string;
}

/**
 * Standalone Ambient LightSweep Component
 *
 * Renders a full-viewport, GPU-accelerated soft ambient starlight sweep across the background.
 * The high-intensity primary white flash has been removed per user request.
 */
export const LightSweep: React.FC<LightSweepProps> = ({
  cycleDuration = 8.5,
  peakOpacity = 0.35,
  enablePrimarySweep = false,
  enableSecondarySweep = true,
  enableOverlaySheen = false,
  className = "",
}) => {
  const [isTabVisible, setIsTabVisible] = useState(true);

  // Tab visibility listener to pause animations when tab is inactive to conserve GPU
  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsTabVisible(!document.hidden);
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);

  return (
    <>
      <style>{`
        /* Primary Luminous Diagonal Beam: Left to Right (Optional) */
        @keyframes sweepBeamPrimary {
          0% {
            transform: translate3d(-38vw, 0, 0) rotate(18deg);
            opacity: 0;
          }
          3% {
            opacity: 1;
          }
          58% {
            transform: translate3d(118vw, 0, 0) rotate(18deg);
            opacity: 1;
          }
          62% {
            opacity: 0;
            transform: translate3d(118vw, 0, 0) rotate(18deg);
          }
          63% {
            opacity: 0;
            transform: translate3d(-38vw, 0, 0) rotate(18deg);
          }
          100% {
            opacity: 0;
            transform: translate3d(-38vw, 0, 0) rotate(18deg);
          }
        }

        /* Secondary Ambient Counter-Sweep: Right to Left */
        @keyframes sweepBeamSecondary {
          0% {
            transform: translate3d(118vw, 0, 0) rotate(-15deg);
            opacity: 0;
          }
          5% {
            opacity: 1;
          }
          55% {
            transform: translate3d(-38vw, 0, 0) rotate(-15deg);
            opacity: 1;
          }
          60% {
            opacity: 0;
            transform: translate3d(-38vw, 0, 0) rotate(-15deg);
          }
          61% {
            opacity: 0;
            transform: translate3d(118vw, 0, 0) rotate(-15deg);
          }
          100% {
            opacity: 0;
            transform: translate3d(118vw, 0, 0) rotate(-15deg);
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .light-sweep-beam,
          .light-sweep-sheen {
            animation: none !important;
            display: none !important;
          }
        }
      `}</style>

      {/* Layer 1: Background Ambient Beam Layer (z-[1]) */}
      <div
        className={`fixed inset-0 pointer-events-none z-[1] overflow-hidden select-none ${className}`}
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 1,
          pointerEvents: "none",
          mixBlendMode: "screen",
        }}
        aria-hidden="true"
      >
        {/* Optional Primary Radiant Beam (Disabled by default: white flash removed) */}
        {enablePrimarySweep && (
          <div
            className="light-sweep-beam absolute pointer-events-none will-change-transform"
            style={{
              width: "560px",
              height: "260vh",
              left: 0,
              top: "-80vh",
              background: `linear-gradient(
                90deg,
                transparent 0%,
                rgba(56, 189, 248, 0.02) 15%,
                rgba(56, 189, 248, 0.12) 36%,
                rgba(255, 255, 255, ${peakOpacity}) 50%,
                rgba(56, 189, 248, 0.12) 64%,
                rgba(56, 189, 248, 0.02) 85%,
                transparent 100%
              )`,
              filter: "blur(14px)",
              boxShadow: "0 0 65px rgba(56, 189, 248, 0.18)",
              animationName: "sweepBeamPrimary",
              animationDuration: `${cycleDuration}s`,
              animationTimingFunction: "cubic-bezier(0.25, 0.1, 0.25, 1)",
              animationIterationCount: "infinite",
              animationPlayState: isTabVisible ? "running" : "paused",
              willChange: "transform, opacity",
            }}
          />
        )}

        {/* Calm Secondary Ambient Counter-Sweep (Pure soft cyan starlight, zero white flash) */}
        {enableSecondarySweep && (
          <div
            className="light-sweep-beam absolute pointer-events-none will-change-transform"
            style={{
              width: "480px",
              height: "260vh",
              left: 0,
              top: "-80vh",
              background: `linear-gradient(
                90deg,
                transparent 0%,
                rgba(56, 189, 248, 0.01) 20%,
                rgba(56, 189, 248, 0.07) 38%,
                rgba(224, 242, 254, 0.14) 50%,
                rgba(56, 189, 248, 0.07) 62%,
                rgba(56, 189, 248, 0.01) 80%,
                transparent 100%
              )`,
              filter: "blur(20px)",
              animationName: "sweepBeamSecondary",
              animationDuration: "12s",
              animationTimingFunction: "cubic-bezier(0.25, 0.1, 0.25, 1)",
              animationIterationCount: "infinite",
              animationPlayState: isTabVisible ? "running" : "paused",
              willChange: "transform, opacity",
            }}
          />
        )}
      </div>

      {/* Layer 2: Foreground Specular Sheen Layer (Disabled by default) */}
      {enableOverlaySheen && enablePrimarySweep && (
        <div
          className="fixed inset-0 pointer-events-none z-20 overflow-hidden select-none"
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 20,
            pointerEvents: "none",
            mixBlendMode: "screen",
          }}
          aria-hidden="true"
        >
          <div
            className="light-sweep-sheen absolute pointer-events-none will-change-transform"
            style={{
              width: "560px",
              height: "260vh",
              left: 0,
              top: "-80vh",
              background: `linear-gradient(
                90deg,
                transparent 0%,
                rgba(255, 255, 255, 0.01) 25%,
                rgba(56, 189, 248, 0.05) 40%,
                rgba(255, 255, 255, 0.16) 50%,
                rgba(56, 189, 248, 0.05) 60%,
                rgba(255, 255, 255, 0.01) 75%,
                transparent 100%
              )`,
              filter: "blur(10px)",
              animationName: "sweepBeamPrimary",
              animationDuration: `${cycleDuration}s`,
              animationTimingFunction: "cubic-bezier(0.25, 0.1, 0.25, 1)",
              animationIterationCount: "infinite",
              animationPlayState: isTabVisible ? "running" : "paused",
              willChange: "transform, opacity",
            }}
          />
        </div>
      )}
    </>
  );
};

export default LightSweep;
