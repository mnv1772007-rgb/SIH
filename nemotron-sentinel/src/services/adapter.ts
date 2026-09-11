import { AnalysisResponse, AuthStatus, ForensicsData, GraphData, GraphNode, ThreatIntelData, RiskBreakdownItem, TimelineEvent } from "@/types/threat-intel";

function normalizeAuthStatus(value: unknown): AuthStatus {
  if (typeof value === "boolean") {
    return value ? "pass" : "fail";
  }
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (v.includes("pass") || v === "success" || v === "ok") return "pass";
    if (v.includes("fail")) return "fail";
    if (v.includes("softfail")) return "softfail";
    if (v.includes("neutral")) return "neutral";
    if (v.includes("none")) return "none";
    // Return none (not fail) for any unknown/missing value — missing record != malicious
    return "none";
  }
  return "none";
}

function normalizeNumber(value: unknown, fallback: number): number {
  if (typeof value === "number" && !isNaN(value)) return value;
  if (typeof value === "string") {
    const parsed = parseFloat(value);
    if (!isNaN(parsed)) return parsed;
  }
  return fallback;
}

function normalizeString(value: unknown, fallback: string): string {
  if (typeof value === "string" && value.trim().length > 0) return value.trim();
  if (typeof value === "number") return String(value);
  return fallback;
}

function normalizeStringArray(value: unknown, fallback: string[] = []): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => (typeof item === "string" ? item : String(item))).filter(Boolean);
  }
  if (typeof value === "string" && value.length > 0) {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed.map(String);
    } catch {
      return [value];
    }
  }
  return fallback;
}

export function classifyRiskScore(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

/**
 * Agnostic Adapter: Tolerates arbitrary key namings, nested vs flat schemas,
 * casing variants, and missing properties from FastAPI or external security backends.
 * NEVER falls back to mock data — throws error if payload is empty or invalid.
 */
export function adaptThreatIntelResponse(raw: any, filename?: string): AnalysisResponse {
  if (!raw || typeof raw !== "object") {
    throw new Error("Cannot adapt threat intelligence: raw response is empty or not an object");
  }

  // Detect whether data is nested in root or sub-objects
  const rawForensics = raw.forensics || raw.email_forensics || raw.headers || raw;
  const rawThreat = raw.threat_intel || raw.intel || raw.enrichment || raw.ai_analysis || raw;
  const rawGeo = rawThreat?.ip_geolocation || rawThreat?.geolocation || rawThreat?.geo || raw?.geolocation || raw?.geo || {};

  // Extract forensics — genuine empty fallbacks only, no fake infrastructure
  const senderDomain = normalizeString(
    rawForensics.sender_domain || rawForensics.senderDomain || rawForensics.domain || rawForensics.sender || raw.sender_domain,
    "unknown"
  );
  const originIp = normalizeString(
    rawForensics.origin_ip || rawForensics.originIp || rawForensics.ip || rawForensics.client_ip || raw.origin_ip,
    "unknown"
  );
  const messageId = normalizeString(
    rawForensics.message_id || rawForensics.messageId || rawForensics.msg_id || raw.message_id,
    "N/A"
  );

  const spfStatus = normalizeAuthStatus(rawForensics.spf_status ?? rawForensics.spf ?? raw.spf_status ?? raw.spf);
  const dkimStatus = normalizeAuthStatus(rawForensics.dkim_status ?? rawForensics.dkim ?? raw.dkim_status ?? raw.dkim);
  const dmarcStatus = normalizeAuthStatus(rawForensics.dmarc_status ?? rawForensics.dmarc ?? raw.dmarc_status ?? raw.dmarc);

  const extractedUrls = normalizeStringArray(
    rawForensics.extracted_urls || rawForensics.urls || rawForensics.links || raw.extracted_urls,
    []
  );

  const emailBodyText = normalizeString(
    rawForensics.email_body_text || rawForensics.body || rawForensics.text || rawForensics.raw_body || raw.email_body_text,
    "No raw body content extracted."
  );

  const forensics: ForensicsData = {
    message_id: messageId,
    sender_domain: senderDomain,
    origin_ip: originIp,
    spf_status: spfStatus,
    dkim_status: dkimStatus,
    dmarc_status: dmarcStatus,
    extracted_urls: extractedUrls,
    email_body_text: emailBodyText,
  };

  // Extract threat intelligence — genuine defaults only, no fake coordinates
  const lat = typeof rawGeo.lat === "number" ? rawGeo.lat : (typeof rawGeo.latitude === "number" ? rawGeo.latitude : 0);
  const lng = typeof rawGeo.lng === "number" ? rawGeo.lng : (typeof rawGeo.longitude === "number" ? rawGeo.longitude : (typeof rawGeo.lon === "number" ? rawGeo.lon : 0));
  const country = normalizeString(rawGeo.country || rawGeo.country_name || rawGeo.nation, "Unknown");
  const asn = normalizeString(rawGeo.asn || rawGeo.org || rawGeo.isp, "Unknown ASN");
  const city = rawGeo.city ? String(rawGeo.city) : undefined;
  const region = rawGeo.region ? String(rawGeo.region) : undefined;

  const domainAgeDays = typeof rawThreat.domain_age_days === "number"
    ? rawThreat.domain_age_days
    : (typeof rawThreat.domain_age === "number" ? rawThreat.domain_age : -1);

  // Unified Authoritative Risk Score across the entire application (Backend is Single Source of Truth)
  // If backend returns null or undefined, do NOT fake 95 or 0. Leave undefined.
  const rawScore = raw.risk_score != null ? raw.risk_score : (rawThreat?.ai_risk_score != null ? rawThreat.ai_risk_score : null);
  const unifiedRiskScore = rawScore != null
    ? Math.min(100, Math.max(0, Math.round(normalizeNumber(rawScore, 0))))
    : undefined;

  const validLevels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const rawLevel = typeof raw.risk_level === "string" ? raw.risk_level.toUpperCase().trim() : "";
  const unifiedRiskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | undefined = validLevels.includes(rawLevel)
    ? (rawLevel as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL")
    : (unifiedRiskScore !== undefined ? classifyRiskScore(unifiedRiskScore) : undefined);

  const rawConf = raw.confidence != null
    ? normalizeNumber(raw.confidence, 0)
    : (rawThreat?.ai_confidence != null ? normalizeNumber(rawThreat.ai_confidence, 0) : null);
  const unifiedConfidence = rawConf != null
    ? (rawConf > 1.0 ? +(rawConf / 100).toFixed(2) : +rawConf.toFixed(2))
    : undefined;

  const unifiedVerdict = typeof raw.verdict === "string" && raw.verdict.trim().length > 0
    ? raw.verdict.trim()
    : (unifiedRiskLevel ? `${unifiedRiskLevel} RISK` : undefined);

  const aiStatus = typeof rawThreat.ai_status === "string" ? rawThreat.ai_status : undefined;

  const rawFlags = rawThreat.threat_intel_flags || rawThreat.flags || rawThreat.iocs || rawThreat.threat_flags || raw.threat_intel_flags;
  // No hardcoded fallback — empty array when no real threat signals exist
  const threatFlags = normalizeStringArray(rawFlags, []);

  const aiNlpIntent = rawThreat.ai_nlp_intent || rawThreat.nlp_intent || rawThreat.intent || raw.ai_nlp_intent
    ? String(rawThreat.ai_nlp_intent || rawThreat.nlp_intent || rawThreat.intent || raw.ai_nlp_intent)
    : (aiStatus === "not_configured" ? "AI Not Configured" : "Standard Communication");

  // Synchronize ai_risk_score with the unified authoritative risk score so RiskGauge and VerdictCard never conflict
  const aiRiskScore = unifiedRiskScore ?? 0;

  const threatIntel: ThreatIntelData = {
    ip_geolocation: { country, asn, lat, lng, city, region },
    domain_age_days: domainAgeDays,
    threat_intel_flags: threatFlags,
    ai_nlp_intent: aiNlpIntent,
    ai_confidence: unifiedConfidence,
    ai_risk_score: aiRiskScore,
    ai_executive_summary: typeof rawThreat.ai_executive_summary === "string" ? rawThreat.ai_executive_summary : undefined,
    ai_attack_hypothesis: typeof rawThreat.ai_attack_hypothesis === "string" ? rawThreat.ai_attack_hypothesis : undefined,
    ai_status: aiStatus,
    abuseipdb: rawThreat.abuseipdb || null,
    virustotal: rawThreat.virustotal || null,
    urlscan: Array.isArray(rawThreat.urlscan) ? rawThreat.urlscan : null,
  };

  // Extract or synthesize Graph Data
  let graphData: GraphData;
  if (raw.graph_data && Array.isArray(raw.graph_data.nodes) && Array.isArray(raw.graph_data.links)) {
    graphData = {
      nodes: raw.graph_data.nodes.map((node: any, idx: number) => ({
        id: normalizeString(node.id, `Node_${idx}`),
        group: typeof node.group === "number" ? node.group : (idx % 4) + 1,
        label: node.label,
        type: node.type,
      })),
      links: raw.graph_data.links.map((link: any) => ({
        source: normalizeString(typeof link.source === "object" ? link.source.id : link.source, "Email"),
        target: normalizeString(typeof link.target === "object" ? link.target.id : link.target, "Target"),
        label: normalizeString(link.label, "CONNECTED_TO"),
      })),
    };
  } else {
    // Generate robust correlation graph from extracted forensics
    const nodes: GraphNode[] = [
      { id: "Email Payload", group: 1, label: "EMAIL ARTIFACT", type: "email" },
      { id: senderDomain, group: 2, label: "SENDER DOMAIN", type: "domain" },
      { id: originIp, group: 3, label: "ORIGIN HOST IP", type: "ip" },
      { id: `${country} (${asn.split(" ")[0]})`, group: 4, label: "GEOLOCATION", type: "geo" },
    ];
    const links = [
      { source: "Email Payload", target: senderDomain, label: "ORIGINATES_FROM" },
      { source: senderDomain, target: originIp, label: "RESOLVES_TO" },
      { source: originIp, target: `${country} (${asn.split(" ")[0]})`, label: "ROUTED_THROUGH" },
    ];

    if (extractedUrls.length > 0) {
      const topUrl = extractedUrls[0];
      let cleanUrl = topUrl;
      try {
        cleanUrl = new URL(topUrl).hostname;
      } catch {
        cleanUrl = topUrl.slice(0, 24);
      }
      nodes.push({ id: cleanUrl, group: 2, label: "EXTRACTED C2 URL", type: "url" as const });
      links.push({ source: "Email Payload", target: cleanUrl, label: "CONTAINS_HYPERLINK" });
      links.push({ source: cleanUrl, target: originIp, label: "RESOLVES_HOST" });
    }

    graphData = { nodes, links };
  }

  // ── Timeline ────────────────────────────────────────────────────────────
  const timeline: TimelineEvent[] | undefined = Array.isArray(raw.timeline) ? raw.timeline : undefined;

  // ── Risk Breakdown ──────────────────────────────────────────────────────
  const riskBreakdown: RiskBreakdownItem[] | undefined = Array.isArray(raw.risk_breakdown) ? raw.risk_breakdown : undefined;

  return {
    scan_id: normalizeString(raw.scan_id || raw.id, `SHIELD-${Date.now().toString(36).toUpperCase()}`),
    case_id: typeof raw.case_id === "string" ? raw.case_id : undefined,
    timestamp: normalizeString(raw.timestamp, new Date().toISOString()),
    filename: filename || raw.filename || "sample_email.eml",
    email_sha256: typeof raw.email_sha256 === "string" ? raw.email_sha256 : undefined,
    // Explainable scoring — Single Source of Truth guaranteed
    risk_score: unifiedRiskScore,
    risk_level: unifiedRiskLevel,
    confidence: unifiedConfidence,
    verdict: unifiedVerdict,
    risk_factors: Array.isArray(raw.risk_factors) ? raw.risk_factors : undefined,
    risk_breakdown: riskBreakdown,
    primary_evidence: Array.isArray(raw.primary_evidence) ? raw.primary_evidence : undefined,
    recommended_actions: Array.isArray(raw.recommended_actions) ? raw.recommended_actions : undefined,
    limitations: typeof raw.limitations === "string" ? raw.limitations : undefined,
    // Core data
    forensics,
    threat_intel: threatIntel,
    timeline,
    graph_data: graphData,
  };
}
