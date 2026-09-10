"use client";

import React from "react";
import { motion } from "framer-motion";
import { Shield, FileText, Globe as GlobeIcon, Server } from "lucide-react";
import { ForensicsData, ThreatIntelData } from "@/types/threat-intel";
import { SectionHeader } from "@/components/dashboard/SectionHeader";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { MetricCard } from "@/components/dashboard/MetricCard";

interface ForensicsSectionProps {
  forensics: ForensicsData;
  threatIntel: ThreatIntelData;
}

export const ForensicsSection: React.FC<ForensicsSectionProps> = ({
  forensics,
  threatIntel,
}) => {
  return (
    <motion.section
      initial={{ opacity: 0, y: 25 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.1 }}
      className="space-y-5"
    >
      <SectionHeader
        title="Authentication & Header Forensics"
        icon={<Shield className="w-5 h-5" />}
        subtitle="Cryptographic validation of sender policies & MIME identity"
        badge="RFC-5322 FORENSICS"
      />

      {/* Auth Status Badges Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatusBadge
          label="SPF"
          status={forensics.spf_status}
          description="Sender Policy Framework DNS validation"
          recordValue={`Origin IP: ${forensics.origin_ip}`}
        />
        <StatusBadge
          label="DKIM"
          status={forensics.dkim_status}
          description="DomainKeys Identified Mail cryptographic signature"
          recordValue={`Domain: ${forensics.sender_domain}`}
        />
        <StatusBadge
          label="DMARC"
          status={forensics.dmarc_status}
          description="Domain-based Message Authentication & Enforcement"
          recordValue="Policy: Quarantine / Reject"
        />
      </div>

      {/* Key Forensics Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard
          label="Message ID"
          value={forensics.message_id}
          icon={<FileText className="w-4 h-4" />}
          subtitle="Unique SMTP tracking header"
          className="font-mono text-xs truncate"
        />
        <MetricCard
          label="Sender Domain"
          value={forensics.sender_domain}
          icon={<GlobeIcon className="w-4 h-4" />}
          trend={
            forensics.sender_domain === "unknown"
              ? "Unresolved Domain"
              : (forensics.spf_status === "pass" && forensics.dkim_status === "pass")
              ? "✓ Cryptographically Verified"
              : (forensics.spf_status === "fail" || forensics.dmarc_status === "fail")
              ? "⚠ Auth Failure Detected"
              : "Standard Domain"
          }
          trendColor={
            forensics.sender_domain === "unknown"
              ? "blue"
              : (forensics.spf_status === "pass" && forensics.dkim_status === "pass")
              ? "blue"
              : (forensics.spf_status === "fail" || forensics.dmarc_status === "fail")
              ? "red"
              : "blue"
          }
          subtitle="Punycode & Protocol inspection"
        />
        <MetricCard
          label="Origin Host IP"
          value={forensics.origin_ip}
          icon={<Server className="w-4 h-4" />}
          trend={
            forensics.origin_ip === "unknown"
              ? "Internal Relay"
              : (threatIntel.ip_geolocation?.asn?.split(" ")[0] || "AS Autonomous")
          }
          trendColor={forensics.origin_ip === "unknown" ? "blue" : "amber"}
          subtitle={
            forensics.origin_ip === "unknown"
              ? "Origin MTA hops internal"
              : `Routed: ${threatIntel.ip_geolocation?.country || "Unknown"}`
          }
        />
      </div>
    </motion.section>
  );
};
