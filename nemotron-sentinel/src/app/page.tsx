"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Zap, RotateCcw, Globe2, ShieldCheck, Sparkles, FileDown } from "lucide-react";
import { AnalysisResponse } from "@/types/threat-intel";
import { defaultMockThreatResponse } from "@/data/mockThreatData";
import { analyzeEmailFile, analyzeDemoSimulation, checkApiHealth } from "@/services/api";
import { generateThreatReportPdf } from "@/services/pdfReportGenerator";
import { Header } from "@/components/dashboard/Header";
import { FileDropZone } from "@/components/dashboard/FileDropZone";
import { GlobeView } from "@/components/dashboard/GlobeView";
import { ForensicsSection } from "@/components/dashboard/ForensicsSection";
import { ThreatIntelSection } from "@/components/dashboard/ThreatIntelSection";
import { GraphSection } from "@/components/dashboard/GraphSection";
import { MitreAttackSection } from "@/components/dashboard/MitreAttackSection";
import { EmailBodyPreview } from "@/components/dashboard/EmailBodyPreview";
import { GlobalThreatFeedSection } from "@/components/dashboard/GlobalThreatFeedSection";
import { Footer } from "@/components/dashboard/Footer";
import { VerdictCard } from "@/components/dashboard/VerdictCard";
import { ForensicTimeline } from "@/components/dashboard/ForensicTimeline";
import { ToastContainer, ToastMessage } from "@/components/ui/Toast";

// User reference coordinates (San Francisco client HQ)
const USER_LAT = 37.7749;
const USER_LNG = -122.4194;

export default function SheildMailDashboard() {
  const [analysisData, setAnalysisData] = useState<AnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [showDashboard, setShowDashboard] = useState(false);
  const [isBackendLive, setIsBackendLive] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // Check backend health on mount
  useEffect(() => {
    let isMounted = true;
    checkApiHealth().then((isLive) => {
      if (isMounted) setIsBackendLive(isLive);
    });
    return () => {
      isMounted = false;
    };
  }, []);

  const addToast = useCallback(
    (toast: Omit<ToastMessage, "id">) => {
      const id = Math.random().toString(36).substring(2, 9);
      setToasts((prev) => [...prev, { ...toast, id }]);
    },
    []
  );

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Handle true file upload (.eml or .msg) via FormData
  const handleFileSelect = useCallback(
    async (file: File) => {
      setIsAnalyzing(true);
      setShowDashboard(false);

      try {
        const result = await analyzeEmailFile(file);

        // If backend was unreachable, notify user with demo toast
        if (result.isDemoFallback) {
          addToast({
            type: "warning",
            title: "API Offline — Running in Demo Mode",
            description:
              result.message ||
              "Backend server unreachable. SheildMail has loaded high-fidelity mock threat forensics.",
            duration: 7000,
          });
        } else {
          addToast({
            type: "success",
            title: "Live Analysis Complete",
            description: `Successfully analyzed payload "${file.name}" via SheildMail API.`,
            duration: 5000,
          });
        }

        setAnalysisData(result.data);
        setShowDashboard(true);
      } catch (err: any) {
        addToast({
          type: "error",
          title: "Analysis Failure",
          description: err?.message || "An unexpected error occurred during payload analysis.",
        });
        setAnalysisData(defaultMockThreatResponse);
        setShowDashboard(true);
      } finally {
        setIsAnalyzing(false);
      }
    },
    [addToast]
  );

  // Handle instant demo trigger
  const handleRunSample = useCallback(async () => {
    setIsAnalyzing(true);
    setShowDashboard(false);

    try {
      const result = await analyzeDemoSimulation("urgent_account_security_alert.eml");
      addToast({
        type: "info",
        title: "Sample Telemetry Initialized",
        description: "Simulated spear-phishing payload loaded for demonstration.",
        duration: 5000,
      });
      setAnalysisData(result.data);
      setShowDashboard(true);
    } finally {
      setIsAnalyzing(false);
    }
  }, [addToast]);

  const handleReset = () => {
    setAnalysisData(null);
    setShowDashboard(false);
    setIsAnalyzing(false);
  };

  const handleDownloadPdf = useCallback(() => {
    if (!analysisData) return;
    try {
      generateThreatReportPdf(analysisData);
      addToast({
        type: "success",
        title: "Forensic PDF Generated",
        description: `Exported incident report for "${analysisData.filename || "payload.eml"}" as PDF.`,
        duration: 5000,
      });
    } catch (err: any) {
      addToast({
        type: "error",
        title: "PDF Export Error",
        description: err?.message || "Could not generate PDF report.",
      });
    }
  }, [analysisData, addToast]);

  // Staggered motion container variants
  const dashboardContainerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.1,
      },
    },
    exit: {
      opacity: 0,
      y: -20,
      transition: { duration: 0.3 },
    },
  };

  return (
    <div className="min-h-screen bg-transparent text-white font-sans antialiased relative selection:bg-red-500/30 selection:text-white">
      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Cyber Background Mesh Glows (Obsidian Black, Deep Red & Cold Cyan) */}
      <div className="fixed inset-0 -z-10 overflow-hidden pointer-events-none">
        {/* Core Red center glow */}
        <div
          className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[900px] h-[900px] rounded-full blur-[240px] opacity-[0.14]"
          style={{ background: "radial-gradient(circle, #ef4444 0%, transparent 70%)" }}
        />
        {/* Secondary Cold Ice Blue Cyber Glow */}
        <div
          className="absolute top-0 right-0 w-[650px] h-[650px] rounded-full blur-[220px] opacity-[0.08]"
          style={{ background: "radial-gradient(circle, #0284c7 0%, transparent 70%)" }}
        />
        {/* Threat Ruby Red Accent Glow */}
        <div
          className="absolute bottom-10 left-10 w-[550px] h-[550px] rounded-full blur-[220px] opacity-[0.08]"
          style={{ background: "radial-gradient(circle, #991b1b 0%, transparent 70%)" }}
        />
        {/* High-tech matrix grid */}
        <div
          className="absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage: `
              linear-gradient(rgba(239, 68, 68, 0.2) 1px, transparent 1px),
              linear-gradient(90deg, rgba(239, 68, 68, 0.2) 1px, transparent 1px)
            `,
            backgroundSize: "64px 64px",
          }}
        />
      </div>

      {/* Futuristic Header */}
      <Header
        isBackendLive={isBackendLive}
        scanId={analysisData?.scan_id}
        onRunDemo={handleRunSample}
      />

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        {/* Top Hero Section */}
        <section className="mb-10">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
            {/* Left: Headline & Upload Drop Zone */}
            <div className="lg:col-span-7 flex flex-col justify-between space-y-6">
              <motion.div
                initial={{ opacity: 0, y: 25 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
              >
                <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono font-semibold tracking-wider mb-4 shadow-[0_0_20px_rgba(239,68,68,0.15)]">
                  <Zap className="w-3.5 h-3.5 text-red-400" />
                  <span>AUTONOMOUS THREAT INTELLIGENCE CONSOLE</span>
                </div>

                <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight leading-[1.15] mb-4">
                  Email Threat Detection <br />
                  <span className="gradient-text">Powered by SheildMail AI</span>
                </h1>

                <p className="text-zinc-400 text-sm sm:text-base leading-relaxed max-w-xl font-mono">
                  Deep cryptographic header authentication, zero-day NLP intent classification, 
                  threat intelligence correlation, and 3D geolocation telemetry synthesized in real time.
                </p>
              </motion.div>

              <FileDropZone
                onFileSelect={handleFileSelect}
                onSampleSelect={handleRunSample}
                isAnalyzing={isAnalyzing}
                onErrorToast={(msg) =>
                  addToast({ type: "error", title: "Upload Warning", description: msg })
                }
              />
            </div>

            {/* Right: 3D Globe Threat Map */}
            <div className="lg:col-span-5">
              <motion.div
                initial={{ opacity: 0, x: 30 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.6, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
                className="h-full flex flex-col justify-between"
              >
                <div className="glass-panel p-4 md:p-5 h-full flex flex-col justify-between">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-red-500/20 border border-red-500/30 flex items-center justify-center text-red-400">
                        <Globe2 className="w-4 h-4" />
                      </div>
                      <div>
                        <h3 className="font-bold text-base text-white tracking-tight">
                          Global Threat Origin Map
                        </h3>
                        <p className="text-[11px] text-zinc-400 font-mono">
                          3D Interactive Geolocation Projection
                        </p>
                      </div>
                    </div>

                    <span className="text-[10px] font-mono text-red-400 px-2.5 py-1 rounded-full bg-red-500/15 border border-red-500/30 font-bold">
                      WEBGL 3D
                    </span>
                  </div>

                  {/* 3D Globe with Dynamic Sizing */}
                  <GlobeView
                    originLat={USER_LAT}
                    originLng={USER_LNG}
                    originLabel="Client (San Francisco, US)"
                    destinationLat={
                      analysisData
                        ? analysisData.threat_intel.ip_geolocation.lat
                        : 55.0084
                    }
                    destinationLng={
                      analysisData
                        ? analysisData.threat_intel.ip_geolocation.lng
                        : 82.9357
                    }
                    destinationLabel={
                      analysisData
                        ? `${analysisData.threat_intel.ip_geolocation.country}`
                        : "RU (Novosibirsk)"
                    }
                  />

                  {/* Location Coordinate Indicators */}
                  <div className="mt-4 grid grid-cols-2 gap-3 text-center">
                    <div className="glass-card p-3">
                      <p className="text-[10px] text-zinc-400 uppercase font-mono tracking-wider">
                        CLIENT LOCATION
                      </p>
                      <p className="font-mono text-sm text-cyan-400 font-semibold mt-0.5 truncate">
                        US (San Francisco)
                      </p>
                    </div>

                    <div className="glass-card p-3">
                      <p className="text-[10px] text-zinc-400 uppercase font-mono tracking-wider">
                        DETECTED ORIGIN
                      </p>
                      <p className="font-mono text-sm text-red-400 font-semibold mt-0.5 truncate">
                        {analysisData
                          ? analysisData.threat_intel.ip_geolocation.country
                          : "RU (Novosibirsk)"}
                      </p>
                    </div>
                  </div>
                </div>
              </motion.div>
            </div>
          </div>
        </section>

        {/* Dynamic Analysis Dashboard with Staggered 60fps Reveal */}
        <AnimatePresence mode="wait">
          {showDashboard && analysisData && (
            <motion.div
              key="analysis-dashboard"
              variants={dashboardContainerVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
              className="space-y-8"
            >
              {/* Scan Telemetry Metadata & Reset Toolbar */}
              <motion.div
                variants={{
                  hidden: { opacity: 0, y: 15 },
                  visible: { opacity: 1, y: 0 },
                }}
                className="glass-card px-5 py-3.5 flex flex-wrap items-center justify-between gap-4 border border-white/10"
              >
                <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500">SCAN ID:</span>
                    <span className="text-red-400 font-bold">
                      {analysisData.scan_id || "SHIELD-SCAN-ACTIVE"}
                    </span>
                  </div>

                  <span className="text-zinc-700 hidden sm:inline">|</span>

                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500">PAYLOAD:</span>
                    <span className="text-zinc-200 font-medium truncate max-w-[220px]">
                      {analysisData.filename || "payload.eml"}
                    </span>
                  </div>

                  <span className="text-zinc-700 hidden sm:inline">|</span>

                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500">TIMESTAMP:</span>
                    <span className="text-zinc-300">
                      {new Date(analysisData.timestamp || Date.now()).toLocaleTimeString()}
                    </span>
                  </div>

                  {analysisData.case_id && (
                    <>
                      <span className="text-zinc-700 hidden sm:inline">|</span>
                      <div className="flex items-center gap-2">
                        <span className="text-zinc-500">CASE:</span>
                        <span className="text-emerald-400 font-bold">{analysisData.case_id}</span>
                      </div>
                    </>
                  )}
                </div>

                <div className="flex items-center gap-2.5">
                  <motion.button
                    whileHover={{ scale: 1.03, y: -1 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={handleDownloadPdf}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 via-red-500 to-red-700 hover:from-red-500 hover:to-red-600 text-white border border-red-500/50 shadow-[0_0_20px_rgba(239,68,68,0.35)] text-xs font-mono font-bold transition-all"
                  >
                    <FileDown className="w-3.5 h-3.5 text-white" />
                    <span>DOWNLOAD PDF REPORT</span>
                  </motion.button>

                  <motion.button
                    whileHover={{ scale: 1.03, y: -1 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={handleReset}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-zinc-300 hover:text-white text-xs font-mono font-medium transition-all"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>NEW SCAN</span>
                  </motion.button>
                </div>
              </motion.div>

              {/* Verdict + Risk Breakdown Card */}
              <VerdictCard data={analysisData} />

              {/* Section A: Authentication & Header Forensics */}
              <ForensicsSection
                forensics={analysisData.forensics}
                threatIntel={analysisData.threat_intel}
              />

              {/* Section A2: Forensic Timeline */}
              {analysisData.timeline && analysisData.timeline.length > 0 && (
                <ForensicTimeline events={analysisData.timeline} />
              )}

              {/* Section B: Threat Intel & AI Assessment */}
              <ThreatIntelSection
                threatIntel={analysisData.threat_intel}
                forensics={analysisData.forensics}
              />

              {/* Section C: Force Graph Correlation Network */}
              <GraphSection graphData={analysisData.graph_data} />

              {/* Section D: MITRE ATT&CK Matrix & Attribution */}
              <MitreAttackSection
                threatIntel={analysisData.threat_intel}
                forensics={analysisData.forensics}
              />

              {/* Section E: Raw Email Payload Preview */}
              <EmailBodyPreview
                emailBodyText={analysisData.forensics.email_body_text}
              />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Empty State / Initial Landing State with Live SOC Feed */}
        {!showDashboard && !isAnalyzing && (
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="space-y-10"
          >
            <div className="text-center py-10 px-4">
              <div className="inline-flex items-center justify-center w-24 h-24 rounded-3xl bg-black/60 border border-red-500/20 shadow-[0_0_40px_rgba(239,68,68,0.15)] mb-6 text-red-400">
                <ShieldCheck className="w-12 h-12 stroke-[1.5]" />
              </div>

              <h2 className="text-2xl font-bold text-white mb-2 tracking-tight">
                Awaiting Email Forensic Payload
              </h2>

              <p className="text-zinc-400 text-sm font-mono max-w-lg mx-auto leading-relaxed mb-6">
                Drop an authentic .eml or .msg file above or trigger our quick sample to run the
                SheildMail multi-stage neural inspection pipeline.
              </p>

              <motion.button
                whileHover={{ scale: 1.04, y: -2 }}
                whileTap={{ scale: 0.96 }}
                onClick={handleRunSample}
                className="inline-flex items-center gap-2.5 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 via-red-500 to-red-700 text-white font-mono font-bold text-xs tracking-wider shadow-[0_0_25px_rgba(239,68,68,0.45)] hover:shadow-[0_0_35px_rgba(239,68,68,0.65)] transition-all"
              >
                <Sparkles className="w-4 h-4 text-white" />
                <span>LAUNCH SAMPLE SPEAR-PHISH DEMO</span>
              </motion.button>
            </div>

            {/* Global SOC Defense Telemetry Stream & Metrics */}
            <GlobalThreatFeedSection />
          </motion.div>
        )}
      </main>

      {/* Cyber Footer */}
      <Footer />
    </div>
  );
}