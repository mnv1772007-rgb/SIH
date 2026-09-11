"use client";

import React from "react";
import { motion } from "framer-motion";
import {
  Brain,
  AlertTriangle,
  Bug,
  Target,
  Zap,
  ExternalLink,
  Clock,
  Server,
  MapPin,
  ShieldX,
  ShieldCheck,
  HelpCircle,
  Activity,
} from "lucide-react";
import { ForensicsData, ThreatIntelData } from "@/types/threat-intel";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { ThreatFlag } from "@/components/dashboard/ThreatFlag";
import { CollapsibleCard } from "@/components/dashboard/CollapsibleCard";

interface ThreatIntelSectionProps {
  threatIntel: ThreatIntelData;
  forensics: ForensicsData;
  riskScore?: number;
}

// ── Status pill helpers ─────────────────────────────────────────────────────
function StatusPill({
  status,
  label,
}: {
  status: "bad" | "suspicious" | "clean" | "unknown";
  label: string;
}) {
  const cfg = {
    bad:        { bg: "bg-red-500/20 border-red-500/40 text-red-300",     icon: <ShieldX className="w-3 h-3" /> },
    suspicious: { bg: "bg-orange-500/20 border-orange-500/40 text-orange-300", icon: <AlertTriangle className="w-3 h-3" /> },
    clean:      { bg: "bg-emerald-500/20 border-emerald-500/40 text-emerald-300", icon: <ShieldCheck className="w-3 h-3" /> },
    unknown:    { bg: "bg-zinc-500/20 border-zinc-500/30 text-zinc-400",   icon: <HelpCircle className="w-3 h-3" /> },
  }[status];
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-mono font-bold ${cfg.bg}`}>
      {cfg.icon}{label}
    </span>
  );
}

function ThreatApiCard({
  title,
  data,
}: {
  title: string;
  data: Record<string, unknown> | null | undefined;
}) {
  if (!data || typeof data !== "object") {
    return (
      <div className="flex items-center justify-between py-2 px-3 rounded-lg bg-white/[0.02] border border-white/5">
        <span className="text-[11px] text-zinc-400 font-mono">{title}</span>
        <StatusPill status="unknown" label="NOT CONFIGURED" />
      </div>
    );
  }

  const status = String(data.status || "").toLowerCase();
  const unavailableStatuses = ["not_configured", "disabled", "error", "unavailable", "timeout", "api_error"];
  if (unavailableStatuses.includes(status)) {
    return (
      <div className="flex items-center justify-between py-2 px-3 rounded-lg bg-white/[0.02] border border-white/5">
        <span className="text-[11px] text-zinc-400 font-mono">{title}</span>
        <StatusPill status="unknown" label="UNAVAILABLE" />
      </div>
    );
  }

  const malicious = Boolean(data.malicious);
  const score = typeof data.abuse_confidence_score === "number" ? data.abuse_confidence_score
    : typeof data.score === "number" ? data.score : null;
  const detections = typeof data.malicious_count === "number" ? data.malicious_count : null;

  let pillStatus: "bad" | "suspicious" | "clean" | "unknown" = "unknown";
  let pillLabel = "UNKNOWN";

  if (status === "not_found") {
    pillStatus = "unknown";
    pillLabel = "NOT FOUND";
  } else if (malicious) {
    if (score !== null && score < 75) {
      pillStatus = "suspicious";
      pillLabel = score !== null ? `${score}% SUSPICIOUS` : "SUSPICIOUS";
    } else {
      pillStatus = "bad";
      pillLabel = detections !== null ? `${detections} DETECTIONS` : "MALICIOUS";
    }
  } else {
    pillStatus = "clean";
    pillLabel = score !== null ? `${score}% CLEAN` : "CLEAN";
  }

  return (
    <div className="flex items-center justify-between py-2 px-3 rounded-lg bg-white/[0.02] border border-white/5">
      <span className="text-[11px] text-zinc-400 font-mono">{title}</span>
      <StatusPill status={pillStatus} label={pillLabel} />
    </div>
  );
}

export const ThreatIntelSection: React.FC<ThreatIntelSectionProps> = ({
  threatIntel,
  forensics,
  riskScore,
}) => {
  const abuseData = threatIntel.abuseipdb as Record<string, unknown> | null | undefined;
  const vtData = threatIntel.virustotal as Record<string, unknown> | null | undefined;
  const vtUrls = Array.isArray((vtData as any)?.urls) ? (vtData as any).urls : [];
  const vtHashes = Array.isArray((vtData as any)?.hashes) ? (vtData as any).hashes : [];
  const urlscanResults = Array.isArray(threatIntel.urlscan) ? threatIntel.urlscan as Record<string, unknown>[] : [];

  const hasRealApiData = abuseData || vtData || urlscanResults.length > 0;
  const authoritativeScore = typeof riskScore === "number" ? riskScore : threatIntel.ai_risk_score;

  return (
    <motion.section
      initial={{ opacity: 0, y: 25 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.2 }}
      className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start"
    >
      {/* Left Column: Risk Gauge */}
      <div className="lg:col-span-1">
        <RiskGauge
          score={authoritativeScore}
          title="FORENSIC THREAT INDEX"
          subtitle="Harmonized forensic threat evaluation"
        />
      </div>

      {/* Right Column: AI Intent & Threat Intel Feeds */}
      <div className="lg:col-span-2 space-y-4">
        {/* NLP Intent Card */}
        <CollapsibleCard
          title="AI Threat Intent Classification"
          icon={<Brain className="w-5 h-5" />}
          badge={
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-bold">
              {threatIntel.ai_status === "not_configured" ? "NOT CONFIGURED" : "NEURAL INFERENCE"}
            </span>
          }
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <MetricCard
              label="Primary Detected Intent"
              value={threatIntel.ai_nlp_intent || "—"}
              icon={<Target className="w-4 h-4" />}
              className="text-base md:text-lg"
              subtitle="Linguistic semantic analysis"
            />
            <MetricCard
              label="Model Confidence"
              value={threatIntel.ai_confidence != null ? `${(threatIntel.ai_confidence * (threatIntel.ai_confidence <= 1 ? 100 : 1)).toFixed(1)}%` : "N/A"}
              icon={<Zap className="w-4 h-4" />}
              trend={threatIntel.ai_status === "not_configured" ? "AI not configured" : "Multi-vector token attention"}
              trendColor={threatIntel.ai_status === "not_configured" ? "red" : "blue"}
              subtitle="Multi-vector token attention"
            />
          </div>

          {/* AI Executive Summary */}
          {threatIntel.ai_executive_summary && (
            <div className="mt-3 p-3 rounded-xl bg-black/40 border border-white/10">
              <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest mb-1.5 flex items-center gap-1.5">
                <Activity className="w-3 h-3" /> EXECUTIVE SUMMARY
              </p>
              <p className="text-xs text-zinc-300 leading-relaxed">{threatIntel.ai_executive_summary}</p>
            </div>
          )}

          {/* AI Attack Hypothesis */}
          {threatIntel.ai_attack_hypothesis && (
            <div className="mt-2 p-3 rounded-xl bg-black/40 border border-white/10">
              <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest mb-1.5">ATTACK HYPOTHESIS</p>
              <p className="text-xs text-zinc-400 leading-relaxed italic">{threatIntel.ai_attack_hypothesis}</p>
            </div>
          )}

          {/* Extracted Hyperlinks */}
          {forensics.extracted_urls && forensics.extracted_urls.length > 0 && (
            <div className="mt-4 p-4 rounded-xl bg-black/50 border border-white/10">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-zinc-400 uppercase tracking-wider">
                  Extracted IOC URLs
                </span>
                <span className="text-[10px] font-mono text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                  {forensics.extracted_urls.length} LINKS
                </span>
              </div>
              <div className="flex flex-col gap-2 max-h-64 overflow-y-auto pr-1">
                {forensics.extracted_urls.map((url, i) => (
                  <a
                    key={i}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-red-500/5 border border-red-500/25 text-red-300 hover:text-white hover:border-red-500/50 hover:bg-red-500/15 transition-all text-xs font-mono truncate group"
                  >
                    <span className="truncate">{url}</span>
                    <ExternalLink className="w-3.5 h-3.5 shrink-0 text-red-400 group-hover:scale-110 transition-transform" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </CollapsibleCard>

        {/* Threat Intel API Results */}
        <CollapsibleCard
          title="Threat Intelligence API Status"
          icon={<AlertTriangle className="w-5 h-5" />}
          badge={
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-bold">
              {threatIntel.threat_intel_flags.length} SIGNALS
            </span>
          }
        >
          {/* Real API result pills */}
          <div className="space-y-1.5 mb-3">
            <ThreatApiCard title="AbuseIPDB — Sending IP" data={abuseData} />
            {vtUrls.length > 0 && vtUrls.map((r: Record<string, unknown>, i: number) => (
              <ThreatApiCard key={i} title={`VirusTotal URL ${i + 1}`} data={r} />
            ))}
            {vtUrls.length === 0 && (
              <ThreatApiCard title="VirusTotal (URLs)" data={vtData} />
            )}
            {vtHashes.length > 0 && vtHashes.map((r: Record<string, unknown>, i: number) => (
              <ThreatApiCard key={i} title={`VirusTotal Hash ${i + 1}`} data={r} />
            ))}
            {urlscanResults.length > 0 && urlscanResults.map((r, i) => (
              <ThreatApiCard key={i} title={`URLScan ${i + 1}`} data={r} />
            ))}
            {!hasRealApiData && (
              <div className="py-2 px-3 rounded-lg bg-white/[0.02] border border-white/5 text-[11px] text-zinc-500 font-mono">
                No threat intelligence APIs configured. Add API keys to .env to enable.
              </div>
            )}
          </div>

          {/* Forensic signals from scoring engine */}
          {threatIntel.threat_intel_flags.length > 0 ? (
            <div className="flex flex-wrap gap-2.5 pt-2 border-t border-white/5">
              {threatIntel.threat_intel_flags.map((flag, idx) => (
                <ThreatFlag key={idx} flag={flag} />
              ))}
            </div>
          ) : (
            <div className="pt-2 border-t border-white/5">
              <p className="text-[11px] text-zinc-600 font-mono">
                ✓ No forensic threat signals detected from this email.
              </p>
            </div>
          )}
        </CollapsibleCard>

        {/* Domain & Infrastructure Intelligence */}
        <CollapsibleCard
          title="Domain & Infrastructure Intelligence"
          icon={<Bug className="w-5 h-5" />}
        >
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <MetricCard
              label="Domain Age"
              value={threatIntel.domain_age_days ? `${threatIntel.domain_age_days} days` : "N/A"}
              icon={<Clock className="w-4 h-4" />}
              trend={
                threatIntel.domain_age_days && threatIntel.domain_age_days < 30
                  ? "⚠ Newly Registered Domain"
                  : "Established Domain"
              }
              trendColor={threatIntel.domain_age_days && threatIntel.domain_age_days < 30 ? "red" : "blue"}
              subtitle="WHOIS epoch analysis"
            />
            <MetricCard
              label="Autonomous System"
              value={threatIntel.ip_geolocation.asn?.split(" ")[0] || "Unknown"}
              icon={<Server className="w-4 h-4" />}
              subtitle={threatIntel.ip_geolocation.asn || "Unknown ASN"}
              className="text-sm"
            />
            <MetricCard
              label="Threat Geolocation"
              value={threatIntel.ip_geolocation.country}
              icon={<MapPin className="w-4 h-4" />}
              subtitle={`Lat: ${(threatIntel.ip_geolocation.lat || 0).toFixed(2)}, Lng: ${(threatIntel.ip_geolocation.lng || 0).toFixed(2)}`}
              trend="Host Country"
              trendColor="red"
            />
          </div>
        </CollapsibleCard>
      </div>
    </motion.section>
  );
};

