export type AuthStatus = "pass" | "fail" | "neutral" | "softfail" | "none";

export interface AttachmentData {
  filename: string;
  content_type: string;
  size_bytes?: number;
  sha256?: string;
  md5?: string;
  is_executable?: boolean;
}

export interface ForensicsData {
  message_id: string;
  sender_domain: string;
  origin_ip: string;
  spf_status: AuthStatus;
  dkim_status: AuthStatus;
  dmarc_status: AuthStatus;
  extracted_urls: string[];
  email_body_text: string;
  attachments?: AttachmentData[];
  smtp_hops?: number;
  headers_anomalies?: {
    reply_to_mismatch?: boolean;
    return_path_mismatch?: boolean;
    display_name_spoofing?: boolean;
  };
}

export interface GeolocationData {
  country: string;
  asn: string;
  lat: number;
  lng: number;
  city?: string;
  region?: string;
}

export interface ThreatIntelData {
  ip_geolocation: GeolocationData;
  domain_age_days: number;
  threat_intel_flags: string[];
  ai_nlp_intent: string;
  ai_confidence?: number;
  ai_risk_score: number;
  ai_executive_summary?: string;
  ai_attack_hypothesis?: string;
  ai_status?: string;
  abuseipdb?: Record<string, unknown> | null;
  virustotal?: Record<string, unknown> | null;
  urlscan?: unknown[] | null;
}

export interface RiskBreakdownItem {
  factor: string;
  category: string;
  points: number;
  reason: string;
}

export interface TimelineEvent {
  timestamp: string;
  category: string;
  event_type: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  metadata?: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  group: number;
  label?: string;
  type?: "email" | "domain" | "ip" | "geo" | "url" | "hop" | "auth" | "attachment" | "hash" | "asn" | "threat" | "identity";
  metadata?: Record<string, unknown>;
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
  value?: number;
  activeFlow?: boolean;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export interface AnalysisResponse {
  forensics: ForensicsData;
  threat_intel: ThreatIntelData;
  graph_data: GraphData;
  filename?: string;
  timestamp?: string;
  scan_id?: string;
  case_id?: string;
  email_sha256?: string;
  // Explainable scoring
  risk_score?: number;
  risk_level?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence?: number;
  verdict?: string;
  risk_factors?: string[];
  risk_breakdown?: RiskBreakdownItem[];
  primary_evidence?: string[];
  recommended_actions?: string[];
  limitations?: string;
  // Timeline
  timeline?: TimelineEvent[];
}

export interface ApiResult<T> {
  data: T;
  isDemoFallback: boolean;
  message?: string;
  error?: string;
}
