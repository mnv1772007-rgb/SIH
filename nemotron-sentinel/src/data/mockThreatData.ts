import { AnalysisResponse } from "@/types/threat-intel";

export const defaultMockThreatResponse: AnalysisResponse = {
  scan_id: "SHIELD-SCAN-2026-982114",
  timestamp: new Date().toISOString(),
  filename: "urgent_account_security_alert.eml",

  // ── Authoritative backend scoring ────────────────────────────────────────
  // These mirror what the backend's explainable_scorer would return.
  // They are used by VerdictCard (Forensic Verdict) as the single source of truth.
  risk_score: 95,
  risk_level: "CRITICAL",
  confidence: 0.97,
  verdict: "CRITICAL RISK - CONFIRMED MALICIOUS INDICATORS",
  risk_breakdown: [
    {
      factor: "TYPOSQUAT DOMAIN",
      category: "ioc",
      points: 20,
      reason: "micros0ft.com detected as typosquatting (0→o substitution) of microsoft.com",
    },
    {
      factor: "SPF FAIL",
      category: "auth",
      points: 10,
      reason: "Sender Policy Framework record explicitly FAILS for sending IP",
    },
    {
      factor: "DKIM FAIL",
      category: "auth",
      points: 10,
      reason: "DKIM cryptographic signature verification failed",
    },
    {
      factor: "DMARC FAIL",
      category: "auth",
      points: 10,
      reason: "DMARC policy enforcement failure — spoofing confirmed",
    },
    {
      factor: "SUSPICIOUS URL",
      category: "ioc",
      points: 20,
      reason: "Credential harvesting URL detected: fake-login-update.com",
    },
    {
      factor: "VERY YOUNG DOMAIN",
      category: "origin",
      points: 15,
      reason: "Sender domain registered only 12 days ago — typical of phishing infrastructure",
    },
    {
      factor: "THREAT INTEL FLAG",
      category: "threat_intel",
      points: 10,
      reason: "IP 198.51.100.14 listed in AbuseIPDB with 100% confidence",
    },
  ],
  primary_evidence: [
    "micros0ft.com is a typosquat of microsoft.com (leetspeak substitution)",
    "SPF, DKIM and DMARC all FAIL — sender authentication completely broken",
    "Credential harvesting URL embedded: fake-login-update.com/auth/verify",
    "Sending IP 198.51.100.14 listed in AbuseIPDB (Confidence: 100%)",
    "Sender domain registered only 12 days ago",
  ],
  recommended_actions: [
    "Do not click any embedded links or open attachments.",
    "Quarantine the email and report to security operations.",
    "Verify sender identity through an out-of-band channel.",
    "Add extracted domains and IPs to gateway blocklists.",
    "Review SPF/DKIM/DMARC DNS records for the sender domain.",
  ],
  limitations:
    "Score based on observable forensic signals only. Does not constitute legal proof. " +
    "IP geolocation and threat-intelligence data are probabilistic. " +
    "Unavailable/unconfigured threat-intel contributes zero risk points.",

  forensics: {
    message_id: "<20260910.849201.sec-notice@micros0ft-security-center.com>",
    sender_domain: "micros0ft.com",
    origin_ip: "198.51.100.14",
    spf_status: "fail",
    dkim_status: "fail",
    dmarc_status: "fail",
    extracted_urls: [
      "http://fake-login-update.com/auth/verify?session=982a7f0",
      "https://account-billing-portal.suspicious-cloud.ru/reset-token",
    ],
    email_body_text: `From: Microsoft Security Team <notifications@micros0ft.com>
To: target-executive@enterprise-client.corp
Subject: IMMEDIATE ACTION REQUIRED: Azure AD Primary Credential Suspension Warning
Date: Wed, 10 Sep 2026 09:42:15 +0000

Dear Enterprise Administrator,

We have detected anomalous sign-in attempts targeting your tenant administrator account from unauthorized IP subnet 198.51.100.14. Pursuant to security directive MS-SEC-991, your corporate single sign-on credentials will be revoked within 60 minutes unless re-authenticated via our emergency portal.

To preserve uninterrupted enterprise tenant access, verify your credentials immediately:
http://fake-login-update.com/auth/verify?session=982a7f0

Reference Incident Code: #AZ-9982-ERR
Microsoft Cloud Sentinel Security Operations`,
  },

  threat_intel: {
    ip_geolocation: {
      country: "RU (Russia)",
      asn: "AS12345 SuspiciousHost Autonomous Net",
      city: "Novosibirsk",
      region: "Siberian Federal District",
      lat: 55.0084,
      lng: 82.9357,
    },
    domain_age_days: 12,
    threat_intel_flags: [
      "AbuseIPDB_Listed (Confidence: 100%)",
      "URLhaus_Active_Malware_Distribution",
      "Typosquatting_High_Similarity",
      "FastFlux_DNS_Behavior",
      "Tor_Exit_Node_Correlated",
    ],
    ai_nlp_intent: "Credential Harvesting & Executive Phishing",
    // ai_confidence kept in 0-1 range; ThreatIntelSection normalizes with (* <=1 ? 100 : 1)
    ai_confidence: 0.968,
    // ai_risk_score must match the authoritative risk_score above so gauge and verdict agree
    ai_risk_score: 95,
    ai_executive_summary:
      "Forensic analysis of this email reveals a high-confidence spear-phishing campaign targeting enterprise Azure AD credentials. " +
      "The sending domain micros0ft.com is a typosquat of microsoft.com using '0' for 'o'. " +
      "SPF, DKIM and DMARC all fail, and the embedded URL routes to a known credential-harvesting endpoint " +
      "hosted on an IP flagged in AbuseIPDB with 100% confidence.",
    ai_attack_hypothesis:
      "Threat actor goal: harvest Azure AD SSO credentials via urgency-driven social engineering. " +
      "Likely campaign: Business Email Compromise / Credential Phishing targeting enterprise administrators.",
    ai_status: "demo",
  },

  graph_data: {
    nodes: [
      { id: "Phishing Email", group: 1, label: "EMAIL SOURCE", type: "email" },
      { id: "micros0ft.com", group: 2, label: "SPOOFED DOMAIN", type: "domain" },
      { id: "198.51.100.14", group: 3, label: "HOSTING IP", type: "ip" },
      { id: "RU (AS12345)", group: 4, label: "GEOLOCATION", type: "geo" },
      { id: "fake-login-update.com", group: 2, label: "HARVESTING C2", type: "url" },
    ],
    links: [
      { source: "Phishing Email", target: "micros0ft.com", label: "SPOOFS_DOMAIN" },
      { source: "micros0ft.com", target: "198.51.100.14", label: "RESOLVES_TO_IP" },
      { source: "198.51.100.14", target: "RU (AS12345)", label: "LOCATED_IN" },
      { source: "Phishing Email", target: "fake-login-update.com", label: "EMBEDS_LINK" },
      { source: "fake-login-update.com", target: "198.51.100.14", label: "HOSTED_BY" },
    ],
  },
};
