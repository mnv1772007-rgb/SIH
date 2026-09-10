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
} from "lucide-react";
import { ForensicsData, ThreatIntelData } from "@/types/threat-intel";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { ThreatFlag } from "@/components/dashboard/ThreatFlag";
import { CollapsibleCard } from "@/components/dashboard/CollapsibleCard";

interface ThreatIntelSectionProps {
  threatIntel: ThreatIntelData;
  forensics: ForensicsData;
}

export const ThreatIntelSection: React.FC<ThreatIntelSectionProps> = ({
  threatIntel,
  forensics,
}) => {
  return (
    <motion.section
      initial={{ opacity: 0, y: 25 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.2 }}
      className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start"
    >
      {/* Left Column: Risk Gauge */}
      <div className="lg:col-span-1">
        <RiskGauge score={threatIntel.ai_risk_score} />
      </div>

      {/* Right Column: AI Intent & Threat Intel Feeds */}
      <div className="lg:col-span-2 space-y-4">
        {/* NLP Intent Card */}
        <CollapsibleCard
          title="AI Threat Intent Classification"
          icon={<Brain className="w-5 h-5" />}
          badge={
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-bold">
              NEURAL INFERENCE
            </span>
          }
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <MetricCard
              label="Primary Detected Intent"
              value={threatIntel.ai_nlp_intent}
              icon={<Target className="w-4 h-4" />}
              className="text-base md:text-lg"
              subtitle="Linguistic semantic analysis"
            />
            <MetricCard
              label="Model Confidence"
              value={`${threatIntel.ai_confidence ?? 95.5}%`}
              icon={<Zap className="w-4 h-4" />}
              trend="High Statistical Confidence"
              trendColor="blue"
              subtitle="Multi-vector token attention"
            />
          </div>

          {/* Extracted Hyperlinks */}
          {forensics.extracted_urls && forensics.extracted_urls.length > 0 && (
            <div className="mt-4 p-4 rounded-xl bg-black/50 border border-white/10">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-zinc-400 uppercase tracking-wider">
                  Extracted Indicators of Compromise (URLs)
                </span>
                <span className="text-[10px] font-mono text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                  {forensics.extracted_urls.length} SUSPICIOUS LINKS
                </span>
              </div>
              <div className="flex flex-col gap-2">
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

        {/* Threat Intel Flags */}
        <CollapsibleCard
          title="Threat Intelligence Feeds & IOC Flags"
          icon={<AlertTriangle className="w-5 h-5" />}
          badge={
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-bold">
              {threatIntel.threat_intel_flags.length} CORRELATIONS
            </span>
          }
        >
          <div className="flex flex-wrap gap-2.5">
            {threatIntel.threat_intel_flags.map((flag, idx) => (
              <ThreatFlag key={idx} flag={flag} />
            ))}
          </div>
        </CollapsibleCard>

        {/* Domain & Infrastructure Intelligence */}
        <CollapsibleCard
          title="Domain & Infrastructure Intelligence"
          icon={<Bug className="w-5 h-5" />}
        >
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <MetricCard
              label="Domain Age"
              value={`${threatIntel.domain_age_days} days`}
              icon={<Clock className="w-4 h-4" />}
              trend={
                threatIntel.domain_age_days < 30
                  ? "⚠ Newly Registered Domain"
                  : "Established Domain"
              }
              trendColor={threatIntel.domain_age_days < 30 ? "red" : "blue"}
              subtitle="WHOIS epoch analysis"
            />
            <MetricCard
              label="Autonomous System"
              value={threatIntel.ip_geolocation.asn.split(" ")[0] || "AS12345"}
              icon={<Server className="w-4 h-4" />}
              subtitle={threatIntel.ip_geolocation.asn}
              className="text-sm"
            />
            <MetricCard
              label="Threat Geolocation"
              value={threatIntel.ip_geolocation.country}
              icon={<MapPin className="w-4 h-4" />}
              subtitle={`Lat: ${threatIntel.ip_geolocation.lat.toFixed(2)}, Lng: ${threatIntel.ip_geolocation.lng.toFixed(2)}`}
              trend="Host Country"
              trendColor="red"
            />
          </div>
        </CollapsibleCard>
      </div>
    </motion.section>
  );
};
