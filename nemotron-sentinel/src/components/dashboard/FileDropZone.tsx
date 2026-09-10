"use client";

import React, { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Upload, Loader2, Sparkles } from "lucide-react";

interface FileDropZoneProps {
  onFileSelect: (file: File) => void;
  onSampleSelect: () => void;
  isAnalyzing: boolean;
  activeScanPhase?: string;
  onErrorToast?: (message: string) => void;
}

const SCAN_STEPS = [
  "MIME Stream Extraction",
  "Header Cryptography (SPF/DKIM)",
  "Neural NLP Intent Analysis",
  "Threat Intel Correlation",
  "Entity Graph Synthesis",
];

export const FileDropZone: React.FC<FileDropZoneProps> = ({
  onFileSelect,
  onSampleSelect,
  isAnalyzing,
  onErrorToast,
}) => {
  const [isDragActive, setIsDragActive] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Cycle scanning step indicators while analyzing
  React.useEffect(() => {
    if (!isAnalyzing) {
      setCurrentStepIndex(0);
      return;
    }
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev + 1) % SCAN_STEPS.length);
    }, 450);
    return () => clearInterval(interval);
  }, [isAnalyzing]);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setIsDragActive(true);
    } else if (e.type === "dragleave") {
      setIsDragActive(false);
    }
  };

  const validateAndSelect = (file: File) => {
    const validExtensions = [".eml", ".msg"];
    const fileNameLower = file.name.toLowerCase();
    const isValid = validExtensions.some((ext) => fileNameLower.endsWith(ext));

    if (!isValid) {
      if (onErrorToast) {
        onErrorToast(`Invalid file format "${file.name}". Please upload a .eml or .msg file.`);
      }
      return;
    }

    if (file.size > 15 * 1024 * 1024) {
      if (onErrorToast) {
        onErrorToast("File size exceeds 15MB maximum threshold.");
      }
      return;
    }

    onFileSelect(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSelect(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSelect(e.target.files[0]);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.1 }}
      className="relative"
    >
      <input
        ref={fileInputRef}
        type="file"
        accept=".eml,.msg"
        onChange={handleFileChange}
        className="hidden"
        disabled={isAnalyzing}
      />

      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !isAnalyzing && fileInputRef.current?.click()}
        className={`glass-panel-glow p-8 md:p-10 text-center cursor-pointer transition-all duration-300 relative overflow-hidden group ${
          isDragActive
            ? "border-red-500 shadow-[0_0_40px_rgba(239,68,68,0.4),inset_0_1px_0_rgba(255,255,255,0.25)] scale-[1.01]"
            : "border-white/10 hover:border-red-500/50 hover:shadow-[0_0_30px_rgba(239,68,68,0.2)]"
        }`}
      >
        {/* Subtle scanline animated pass */}
        <div className="absolute inset-x-0 h-24 bg-gradient-to-b from-transparent via-red-500/10 to-transparent animate-scan-line pointer-events-none" />

        {/* Tactical corner brackets */}
        <div className="hud-corner" />

        {/* Icon & Spinner */}
        <div className="relative inline-flex items-center justify-center mb-5">
          <motion.div
            whileHover={{ scale: 1.05 }}
            className={`w-20 h-20 rounded-2xl flex items-center justify-center border transition-all ${
              isAnalyzing
                ? "bg-black/80 border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.5)]"
                : "bg-black/50 border-white/10 group-hover:border-red-500/60 group-hover:shadow-[0_0_20px_rgba(239,68,68,0.25)]"
            }`}
          >
            {isAnalyzing ? (
              <Loader2 className="w-9 h-9 text-red-400 animate-spin" />
            ) : (
              <Upload className="w-9 h-9 text-zinc-300 group-hover:text-red-400 transition-colors" />
            )}
          </motion.div>
        </div>

        {/* Headings */}
        <h3 className="text-xl md:text-2xl font-bold text-white mb-2 tracking-tight">
          {isAnalyzing ? (
            <span className="gradient-text">SheildMail Neural Pipeline Active</span>
          ) : (
            "Drop Email Payload for AI Forensics"
          )}
        </h3>

        <p className="text-zinc-400 text-sm max-w-md mx-auto mb-5 leading-relaxed font-mono">
          {isAnalyzing
            ? "Extracting headers, parsing MIME structure, correlating threat intelligence & NLP intent..."
            : "Upload an authentic .eml or .msg file to trigger real-time autonomous forensics."}
        </p>

        {/* Supported badges & Quick sample trigger */}
        {!isAnalyzing && (
          <div className="flex flex-wrap items-center justify-center gap-3">
            <span className="px-3 py-1 bg-black/60 rounded-lg border border-white/10 text-xs font-mono text-zinc-300">
              .EML
            </span>
            <span className="px-3 py-1 bg-black/60 rounded-lg border border-white/10 text-xs font-mono text-zinc-300">
              .MSG
            </span>
            <span className="px-3 py-1 bg-black/60 rounded-lg border border-white/10 text-xs font-mono text-zinc-300">
              MAX 15MB
            </span>

            <span className="text-zinc-600 hidden sm:inline">•</span>

            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onSampleSelect();
              }}
              className="inline-flex items-center gap-1.5 px-3.5 py-1 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/40 text-red-300 hover:text-white text-xs font-mono font-semibold transition-colors shadow-[0_0_15px_rgba(239,68,68,0.15)]"
            >
              <Sparkles className="w-3.5 h-3.5 text-red-400" />
              <span>Load Sample Phish</span>
            </button>
          </div>
        )}
      </div>

      {/* Progress status bar when analyzing */}
      <AnimatePresence>
        {isAnalyzing && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="mt-4 glass-panel p-4"
          >
            <div className="flex items-center justify-between mb-2 text-xs font-mono">
              <span className="text-zinc-400 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
                PIPELINE STATUS:
              </span>
              <span className="text-red-400 font-semibold">
                {SCAN_STEPS[currentStepIndex]}
              </span>
            </div>

            {/* Glowing animated progress bar */}
            <div className="h-2 bg-black/70 rounded-full overflow-hidden border border-white/10">
              <motion.div
                initial={{ width: "5%" }}
                animate={{ width: "95%" }}
                transition={{ duration: 2.2, ease: "easeInOut" }}
                className="h-full bg-gradient-to-r from-red-600 via-red-500 to-cyan-400 rounded-full shadow-[0_0_15px_#ef4444]"
              />
            </div>

            {/* Step badges */}
            <div className="grid grid-cols-5 gap-1 mt-3">
              {SCAN_STEPS.map((step, idx) => (
                <div
                  key={step}
                  className={`text-[9px] font-mono text-center py-1 px-0.5 rounded border transition-colors ${
                    idx <= currentStepIndex
                      ? "bg-red-500/20 text-red-300 border-red-500/40"
                      : "bg-black/30 text-zinc-600 border-white/5"
                  }`}
                >
                  {step.split(" ")[0]}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};
