import { AnalysisResponse } from "@/types/threat-intel";

export const defaultMockThreatResponse: AnalysisResponse = {
  scan_id: "SHIELD-SCAN-2026-982114",
  timestamp: new Date().toISOString(),
  filename: "urgent_account_security_alert.eml",
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
    ai_confidence: 96.8,
    ai_risk_score: 94.5,
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
