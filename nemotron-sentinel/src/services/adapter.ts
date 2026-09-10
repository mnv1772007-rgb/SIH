import { AnalysisResponse, AuthStatus, ForensicsData, GraphData, GraphNode, ThreatIntelData, RiskBreakdownItem, TimelineEvent } from "@/types/threat-intel";
import { defaultMockThreatResponse } from "@/data/mockThreatData";

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

/**
 * Agnostic Adapter: Tolerates arbitrary key namings, nested vs flat schemas,
 * casing variants, and missing properties from FastAPI or external security backends.
 */
export function adaptThreatIntelResponse(raw: any, filename?: string): AnalysisResponse {
  if (!raw || typeof raw !== "object") {
    return {
      ...defaultMockThreatResponse,
      filename: filename || defaultMockThreatResponse.filename,
      timestamp: new Date().toISOString(),
    };
  }

  // Detect whether data is nested in root or sub-objects
  const rawForensics = raw.forensics || raw.email_forensics || raw.headers || raw;
  const rawThreat = raw.threat_intel || raw.intel || raw.enrichment || raw.ai_analysis || raw;
  const rawGeo = rawThreat?.ip_geolocation || rawThreat?.geolocation || rawThreat?.geo || raw?.geolocation || raw?.geo || {};

  // Extract forensics
  const senderDomain = normalizeString(
    rawForensics.sender_domain || rawForensics.senderDomain || rawForensics.domain || rawForensics.sender || raw.sender_domain,
    "unknown-origin.net"
  );
  const originIp = normalizeString(
    rawForensics.origin_ip || rawForensics.originIp || rawForensics.ip || rawForensics.client_ip || raw.origin_ip,
    "198.51.100.1"
  );
  const messageId = normalizeString(
    rawForensics.message_id || rawForensics.messageId || rawForensics.msg_id || raw.message_id,
    `<${Date.now()}@sentinel-scan.internal>`
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

  // Extract threat intelligence
  const lat = normalizeNumber(rawGeo.lat ?? rawGeo.latitude, 55.0084);
  const lng = normalizeNumber(rawGeo.lng ?? rawGeo.longitude ?? rawGeo.lon, 82.9357);
  const country = normalizeString(rawGeo.country || rawGeo.country_name || rawGeo.nation, "Unknown Geolocation");
  const asn = normalizeString(rawGeo.asn || rawGeo.org || rawGeo.isp, "AS Autonomous Network");
  const city = rawGeo.city ? String(rawGeo.city) : undefined;
  const region = rawGeo.region ? String(rawGeo.region) : undefined;

  const domainAgeDays = normalizeNumber(
    rawThreat.domain_age_days ?? rawThreat.domain_age ?? rawThreat.domainAge ?? raw.domain_age_days,
    14
  );

  const rawFlags = rawThreat.threat_intel_flags || rawThreat.flags || rawThreat.iocs || rawThreat.threat_flags || raw.threat_intel_flags;
  // No hardcoded fallback — empty array when no real threat signals exist
  const threatFlags = normalizeStringArray(rawFlags, []);

  const aiNlpIntent = normalizeString(
    rawThreat.ai_nlp_intent || rawThreat.nlp_intent || rawThreat.intent || rawThreat.predicted_intent || raw.ai_nlp_intent,
    "Phishing / Social Engineering Attempt"
  );

  const aiConfidence = normalizeNumber(
    rawThreat.ai_confidence ?? rawThreat.confidence ?? rawThreat.confidence_score,
    95.0
  );

  const aiRiskScore = normalizeNumber(
    rawThreat.ai_risk_score ?? rawThreat.risk_score ?? rawThreat.riskScore ?? rawThreat.score ?? raw.ai_risk_score,
    88.0
  );

  const threatIntel: ThreatIntelData = {
    ip_geolocation: { country, asn, lat, lng, city, region },
    domain_age_days: domainAgeDays,
    threat_intel_flags: threatFlags,
    ai_nlp_intent: aiNlpIntent,
    ai_confidence: aiConfidence,
    ai_risk_score: Math.min(100, Math.max(0, aiRiskScore)),
    ai_executive_summary: typeof rawThreat.ai_executive_summary === "string" ? rawThreat.ai_executive_summary : undefined,
    ai_attack_hypothesis: typeof rawThreat.ai_attack_hypothesis === "string" ? rawThreat.ai_attack_hypothesis : undefined,
    ai_status: typeof rawThreat.ai_status === "string" ? rawThreat.ai_status : undefined,
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
    // Explainable scoring — pass through as-is from backend
    risk_score: typeof raw.risk_score === "number" ? raw.risk_score : undefined,
    risk_level: typeof raw.risk_level === "string" ? raw.risk_level as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" : undefined,
    confidence: typeof raw.confidence === "number" ? raw.confidence : undefined,
    verdict: typeof raw.verdict === "string" ? raw.verdict : undefined,
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
