"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { 
  Crosshair, 
  ShieldAlert, 
  ExternalLink, 
  ChevronRight, 
  Flame, 
  Cpu, 
  Lock, 
  Eye, 
  ArrowRightCircle, 
  CheckCircle2 
} from "lucide-react";
import { SectionHeader } from "./SectionHeader";
import { AnalysisResponse } from "@/types/threat-intel";

interface MitreAttackSectionProps {
  threatIntel: AnalysisResponse["threat_intel"];
  forensics: AnalysisResponse["forensics"];
}

interface MitreTechnique {
  id: string;
  tactic: string;
  technique: string;
  confidence: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
  evidence: string;
  subtechniques?: string[];
}

export const MitreAttackSection: React.FC<MitreAttackSectionProps> = ({
  threatIntel,
  forensics,
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<string>("T1566.002");

  const techniques: MitreTechnique[] = [
    {
      id: "T1566.002",
      tactic: "INITIAL ACCESS",
      technique: "Phishing: Spearphishing Link",
      confidence: 98.4,
      severity: "CRITICAL",
      description: "Adversary delivered an urgent credential suspension lure containing a weaponized hyperlink.",
      evidence: forensics.extracted_urls[0] || "Targeted emergency credential verification link",
      subtechniques: ["T1566.002 (Hyperlink Delivery)", "T1204.001 (User Execution)"],
    },
    {
      id: "T1556",
      tactic: "CREDENTIAL ACCESS",
      technique: "Modify Authentication Process: AiTM Proxy",
      confidence: 96.2,
      severity: "CRITICAL",
      description: "Reverse-proxy authentication portal configured to intercept session cookies and bypass MFA.",
      evidence: "Reverse landing portal: fake-login-update.com",
      subtechniques: ["T1556.007 (Hybrid Identity Abuse)", "T1539 (Steal Web Session Cookies)"],
    },
    {
      id: "T1586.002",
      tactic: "DEFENSE EVASION",
      technique: "Homoglyph & Typosquatting Spoof",
      confidence: 99.1,
      severity: "CRITICAL",
      description: `Domain ${forensics.sender_domain} closely imitates trusted vendor with zero ASCII character shift.`,
      evidence: `Sender domain "${forensics.sender_domain}" fails SPF, DKIM, and DMARC checks.`,
      subtechniques: ["T1586.002 (Typosquatted Domain)", "T1036 (Masquerading)"],
    },
    {
      id: "T1071.001",
      tactic: "COMMAND & CONTROL",
      technique: "Application Layer Protocol: Web Protocols",
      confidence: 92.5,
      severity: "HIGH",
      description: "C2 channel utilizes encrypted HTTP/S endpoints hosted on bulletproof autonomous infrastructure.",
      evidence: `Resolved IP: ${forensics.origin_ip} (${threatIntel.ip_geolocation.asn})`,
      subtechniques: ["T1071.001 (Web Traffic)", "T1568.002 (Fast Flux DNS)"],
    },
  ];

  const killChainStages = [
    { name: "Recon", status: "complete", label: "Target Profiled" },
    { name: "Weaponize", status: "complete", label: "AiTM Portal Built" },
    { name: "Delivery", status: "intercepted", label: "Email Neutralized" },
    { name: "Exploit", status: "blocked", label: "Credential Theft Stopped" },
    { name: "C2 Egress", status: "blocked", label: "Channel Quarantined" },
  ];

  const activeTechnique = techniques.find((t) => t.id === selectedTechnique) || techniques[0];

  return (
    <section className="space-y-6">
      <SectionHeader
        title="MITRE ATT&CK Matrix & Attribution"
        icon={<Crosshair className="w-5 h-5 text-red-400" />}
        subtitle="Adversary Tactics, Techniques & Procedures (TTPs) Mapped to Knowledge Base v14"
        badge="ATT&CK v14.1"
      />

      {/* Cyber Kill Chain Progression Stepper */}
      <div className="glass-panel p-5 border border-white/10">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-red-400" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300">
              Lockheed Martin Cyber Kill Chain® Progression
            </h4>
          </div>
          <span className="px-2.5 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono font-bold">
            INTERCEPTED AT STAGE 3 (DELIVERY)
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {killChainStages.map((stage, idx) => {
            const isIntercepted = stage.status === "intercepted";
            const isComplete = stage.status === "complete";
            return (
              <div
                key={stage.name}
                className={`relative p-3 rounded-xl border text-center font-mono ${
                  isIntercepted
                    ? "bg-red-500/15 border-red-500/40 shadow-[0_0_20px_rgba(239,68,68,0.25)]"
                    : isComplete
                    ? "bg-amber-500/10 border-amber-500/30 text-amber-300"
                    : "bg-black/40 border-white/5 text-zinc-500"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 mb-1">
                  <span className="text-[10px] text-zinc-500">0{idx + 1}.</span>
                  <span className="text-xs font-bold text-white uppercase">{stage.name}</span>
                </div>
                <p className={`text-[10px] ${isIntercepted ? "text-red-400 font-bold" : "text-zinc-400"}`}>
                  {stage.label}
                </p>
                {isIntercepted && (
                  <span className="inline-block mt-1.5 px-1.5 py-0.5 rounded bg-red-500 text-black text-[9px] font-bold uppercase tracking-wider">
                    BLOCKED HERE
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* MITRE Techniques Matrix & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Techniques List (7 Cols) */}
        <div className="lg:col-span-7 space-y-3">
          <p className="text-xs font-mono text-zinc-400 flex items-center justify-between">
            <span>IDENTIFIED ATT&CK TECHNIQUES ({techniques.length})</span>
            <span className="text-zinc-500 text-[11px]">Click a technique for telemetry</span>
          </p>

          <div className="space-y-2.5">
            {techniques.map((tech) => {
              const isSelected = selectedTechnique === tech.id;
              return (
                <motion.div
                  key={tech.id}
                  onClick={() => setSelectedTechnique(tech.id)}
                  whileHover={{ scale: 1.01, x: 3 }}
                  whileTap={{ scale: 0.99 }}
                  className={`cursor-pointer p-4 rounded-xl border transition-all ${
                    isSelected
                      ? "bg-gradient-to-r from-red-950/40 via-black to-black border-red-500/50 shadow-[0_0_25px_rgba(239,68,68,0.2)]"
                      : "glass-card hover:border-white/20"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-red-400 bg-red-500/15 border border-red-500/30 px-2 py-0.5 rounded">
                          {tech.id}
                        </span>
                        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                          {tech.tactic}
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-white tracking-tight">
                        {tech.technique}
                      </h4>
                      <p className="text-xs text-zinc-400 line-clamp-1 font-mono">
                        {tech.description}
                      </p>
                    </div>

                    <div className="text-right shrink-0">
                      <span className="text-xs font-mono font-bold text-cyan-400">
                        {tech.confidence}%
                      </span>
                      <p className="text-[10px] font-mono text-zinc-500 uppercase">
                        CONFIDENCE
                      </p>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>

        {/* Selected Technique Deep-Dive Inspector (5 Cols) */}
        <div className="lg:col-span-5">
          <div className="glass-panel p-5 border border-red-500/30 shadow-[0_0_35px_rgba(239,68,68,0.15)] h-full flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/10">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-red-400" />
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300">
                    Technique Analysis
                  </span>
                </div>
                <span className="text-xs font-mono font-bold text-red-400 px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30">
                  {activeTechnique.id}
                </span>
              </div>

              <div className="space-y-4">
                <div>
                  <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
                    TACTIC & TECHNIQUE
                  </span>
                  <p className="text-sm font-bold text-white mt-0.5">
                    {activeTechnique.technique}
                  </p>
                  <p className="text-xs font-mono text-zinc-400 mt-1 leading-relaxed">
                    {activeTechnique.description}
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-black/60 border border-white/10">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
                    EXTRACTED PAYLOAD EVIDENCE
                  </span>
                  <p className="text-xs font-mono text-red-400 font-semibold break-all mt-1">
                    {activeTechnique.evidence}
                  </p>
                </div>

                <div>
                  <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mb-2 block">
                    ASSOCIATED SUB-TECHNIQUES
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {activeTechnique.subtechniques?.map((sub) => (
                      <span
                        key={sub}
                        className="text-[10px] font-mono px-2 py-1 rounded bg-white/5 border border-white/10 text-zinc-300"
                      >
                        {sub}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Threat Attribution Footer */}
            <div className="mt-6 pt-4 border-t border-white/10 bg-black/30 -mx-5 -mb-5 p-4 rounded-b-2xl">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-mono text-zinc-400 uppercase">
                    ATTRIBUTION PATTERN
                  </span>
                  <p className="text-xs font-bold text-amber-400 font-mono">
                    APT29 / Nobelium Emulation
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-[10px] font-mono text-zinc-400 uppercase">
                    SEVERITY
                  </span>
                  <p className="text-xs font-bold text-red-400 font-mono">
                    {activeTechnique.severity}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default MitreAttackSection;
