export type AuthStatus = "pass" | "fail" | "neutral" | "softfail" | "none";

export interface ForensicsData {
  message_id: string;
  sender_domain: string;
  origin_ip: string;
  spf_status: AuthStatus;
  dkim_status: AuthStatus;
  dmarc_status: AuthStatus;
  extracted_urls: string[];
  email_body_text: string;
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
}

export interface GraphNode {
  id: string;
  group: number;
  label?: string;
  type?: "email" | "domain" | "ip" | "geo" | "url";
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
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
}

export interface ApiResult<T> {
  data: T;
  isDemoFallback: boolean;
  message?: string;
  error?: string;
}
