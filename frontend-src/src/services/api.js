// FastAPI client — mirrors the backend API contract:
//   POST /api/analyze (multipart "file") -> full analysis report
//   GET  /api/cases -> list of cases
//   GET  /api/cases/:caseId -> single case report
//   GET  /health -> health check
// The dashboard consumes a FLATTENED schema (see normalizeAnalysis).
// If the backend is unreachable, everything transparently falls back to mock data.

const API_BASE = '/api'
const HEALTH_TIMEOUT_MS = 2500

/** Ping the backend. Returns true when FastAPI is reachable. */
export async function checkHealth() {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS)
    const res = await fetch(`${API_BASE}/health`, { signal: controller.signal })
    clearTimeout(timer)
    return res.ok
  } catch {
    return false
  }
}

// Country → approximate lat/lon, used when the backend omits coordinates.
const COUNTRY_COORDS = {
  RU: [55.75, 37.61], US: [38.9, -77.0], CN: [39.9, 116.4], NL: [52.37, 4.9],
  DE: [52.52, 13.4], BR: [-15.8, -47.9], IN: [28.61, 77.2], UA: [50.45, 30.52],
  GB: [51.5, -0.12], FR: [48.85, 2.35], KR: [37.56, 126.97], JP: [35.68, 139.69],
}

/**
 * Flatten the backend report envelope into the single
 * object consumed by every dashboard panel.
 * 
 * Backend returns:
 * {
 *   case: { case_id, email_id, email_hash, analysis_timestamp, source_name, engine_version },
 *   verdict: { classification, risk_level, risk_score, confidence, factors },
 *   email: { from, from_address, from_display_name, to, cc, bcc, subject, date, reply_to, return_path, message_id },
 *   authentication: { spf: {result, status, display_status, source}, dkim: {...}, dmarc: {...} },
 *   header_analysis: { findings, received_chain, relay_hops, relay_path, origin_candidates, probable_source_infrastructure, legacy_header_risk },
 *   nlp_analysis: { classification, confidence, indicators, explanation, methodology, legacy_analysis },
 *   urls: [{ url, normalized_url, domain, classification, risk_contribution, indicator_details, reputation, threat_intelligence, redirect_analysis }],
 *   ...
 * }
 * 
 * Frontend expects:
 * {
 *   message_id, sender_domain, origin_ip, spf_status, dkim_status, dmarc_status,
 *   extracted_urls, email_body_text,
 *   ip_geolocation: { country, asn, lat, lon },
 *   domain_age_days, threat_intel_flags, ai_nlp_intent, ai_risk_score,
 *   analysis_id, timestamp
 * }
 */
export function normalizeAnalysis(raw) {
  const verdict = raw.verdict ?? {}
  const email = raw.email ?? {}
  const auth = raw.authentication ?? {}
  const header = raw.header_analysis ?? {}
  const nlp = raw.nlp_analysis ?? {}
  const urls = raw.urls ?? []
  const ipAnalysis = raw.ip_analysis ?? []
  const geolocation = raw.geolocation ?? []
  const domainIntel = raw.domain_intelligence ?? []
  const threatIntel = raw.threat_intelligence ?? {}
  const caseInfo = raw.case ?? {}

  // Extract sender domain from email.from_address or email.from
  const senderAddress = email.from_address || email.from || ''
  const senderDomain = senderAddress.includes('@') ? senderAddress.split('@')[1] : 'unknown.tld'

  // Extract origin IP from header analysis
  let originIp = '0.0.0.0'
  if (header.probable_source_infrastructure?.ip) {
    originIp = header.probable_source_infrastructure.ip
  } else if (header.origin_candidates?.length > 0) {
    const globalCandidate = header.origin_candidates.find(c => c.is_global)
    if (globalCandidate) originIp = globalCandidate.ip
  } else if (ipAnalysis.length > 0) {
    const globalIp = ipAnalysis.find(ip => ip.is_global)
    if (globalIp) originIp = globalIp.ip
  }

  // Extract authentication statuses
  const spfStatus = auth.spf?.display_status?.toLowerCase() || auth.spf?.status?.toLowerCase() || auth.spf?.result?.toLowerCase() || 'none'
  const dkimStatus = auth.dkim?.display_status?.toLowerCase() || auth.dkim?.status?.toLowerCase() || auth.dkim?.result?.toLowerCase() || 'none'
  const dmarcStatus = auth.dmarc?.display_status?.toLowerCase() || auth.dmarc?.status?.toLowerCase() || auth.dmarc?.result?.toLowerCase() || 'none'

  // Extract URLs
  const extractedUrls = urls.map(u => u.url).filter(Boolean)

  // Get email body text from header analysis or nlp
  const emailBodyText = nlp.legacy_analysis?.body_text || nlp.legacy_analysis?.text_body || ''

  // Get geolocation from first available IP geolocation record
  let ipGeo = { country: 'XX', asn: 'Unknown', lat: 20, lon: 0 }
  const geoRecord = geolocation.find(g => g.status === 'available' && g.country)
  if (geoRecord) {
    ipGeo = {
      country: geoRecord.country || 'XX',
      asn: geoRecord.asn || geoRecord.isp || 'Unknown',
      lat: geoRecord.latitude ?? geoRecord.lat ?? COUNTRY_COORDS[geoRecord.country]?.[0] ?? 20,
      lon: geoRecord.longitude ?? geoRecord.lon ?? COUNTRY_COORDS[geoRecord.country]?.[1] ?? 0,
    }
  } else if (geolocation.length > 0) {
    const firstGeo = geolocation[0]
    const country = firstGeo.country || 'XX'
    const [lat, lon] = COUNTRY_COORDS[country] ?? [20, 0]
    ipGeo = {
      country,
      asn: firstGeo.asn || firstGeo.isp || 'Unknown',
      lat,
      lon,
    }
  }

  // Get domain age from domain intelligence
  let domainAgeDays = 0
  if (domainIntel.length > 0 && domainIntel[0].static_analysis?.domain_age_days != null) {
    domainAgeDays = domainIntel[0].static_analysis.domain_age_days
  }

  // Collect threat intel flags from URL threat intelligence
  const threatIntelFlags = []
  urls.forEach(url => {
    const ti = url.threat_intelligence
    if (ti) {
      Object.entries(ti).forEach(([source, result]) => {
        if (result && typeof result === 'object' && result.malicious) {
          threatIntelFlags.push(`${source}_Malicious`)
        } else if (result && typeof result === 'object' && result.suspicious) {
          threatIntelFlags.push(`${source}_Suspicious`)
        }
      })
      if (ti.openphish?.malicious) threatIntelFlags.push('OpenPhish_Listed')
    }
  })
  // Add IP threat intel flags
  raw.ip_threat_intelligence?.forEach(item => {
    if (item.malicious) threatIntelFlags.push('AbuseIPDB_Listed')
  })

  // Get NLP intent and risk score
  const aiNlpIntent = nlp.classification || 'Unknown'
  const aiRiskScore = verdict.risk_score ?? 0

  // Get message ID
  const messageId = email.message_id || caseInfo.email_id || '<unknown>'

  // Analysis ID and timestamp
  const analysisId = caseInfo.case_id || raw.analysis_id || null
  const timestamp = caseInfo.analysis_timestamp || raw.timestamp || new Date().toISOString()

  return {
    message_id: messageId,
    sender_domain: senderDomain,
    origin_ip: originIp,
    spf_status: spfStatus,
    dkim_status: dkimStatus,
    dmarc_status: dmarcStatus,
    extracted_urls: extractedUrls,
    email_body_text: emailBodyText,
    ip_geolocation: ipGeo,
    domain_age_days: domainAgeDays,
    threat_intel_flags: threatIntelFlags.length > 0 ? threatIntelFlags : ['No_Threat_Intel'],
    ai_nlp_intent: aiNlpIntent,
    ai_risk_score: aiRiskScore,
    analysis_id: analysisId,
    timestamp: timestamp,
    // Also include full raw data for advanced panels
    _raw: raw,
  }
}

/**
 * Upload an .eml/.msg file for analysis. Uses XHR to report upload progress.
 * Falls back to the local mock pipeline when the backend is offline.
 */
export async function analyzeEmail(file, onProgress = () => {}) {
  const online = await checkHealth()

  if (online) {
    try {
      const raw = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest()
        xhr.open('POST', `${API_BASE}/analyze`)
        xhr.setRequestHeader('Accept', 'application/json')

        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 50))
        }
        xhr.onload = () => {
          try {
            const data = JSON.parse(xhr.responseText)
            if (xhr.status >= 200 && xhr.status < 300) resolve(data)
            else reject(new Error(data.detail || `HTTP ${xhr.status}`))
          } catch {
            reject(new Error('Invalid JSON from backend'))
          }
        }
        xhr.onerror = () => reject(new Error('Network error'))

        const form = new FormData()
        form.append('file', file)
        xhr.send(form)
      })
      onProgress(100)
      return { result: normalizeAnalysis(raw), source: 'api' }
    } catch (err) {
      console.warn('[api] backend analysis failed, using mock:', err.message)
    }
  }

  // ---- offline mock pipeline ----
  const stages = [8, 22, 41, 55, 63, 78, 87, 94, 100]
  for (const p of stages) {
    onProgress(p)
    await new Promise((r) => setTimeout(r, 320))
  }
  return { result: mockAnalysisFromFile(file), source: 'mock' }
}

/** Deterministic-ish mock result derived from the uploaded file name. */
function mockAnalysisFromFile(file) {
  const name = (file?.name ?? 'sample.eml').replace(/\.(eml|msg|txt)$/i, '')
  const seed = [...name].reduce((a, c) => a + c.charCodeAt(0), 0)
  const domains = ['micros0ft.com', 'paypa1-secure.io', 'dhl-track-express.net', 'secure-bank-alert.top', 'appleid-verify.xyz']
  const intents = ['Credential Harvesting', 'Financial Fraud', 'Malware Delivery', 'Business Email Compromise', 'Account Takeover']
  const countries = Object.keys(COUNTRY_COORDS)

  const domain = domains[seed % domains.length]
  const country = countries[seed % countries.length]
  const [lat, lon] = COUNTRY_COORDS[country]
  const risk = Math.round((55 + (seed % 44) + Math.random() * 5) * 10) / 10

  const flags = ['AbuseIPDB_Listed', 'URLhaus_Malware', 'PhishTank_Verified', 'Spamhaus_Listed', 'Domain_Age_Young']
    .filter((_, i) => (seed >> i) % 2 === 1)
  if (flags.length === 0) flags.push('Spamhaus_Listed')

  return {
    message_id: `<${Date.now()}@mx.${domain}>`,
    sender_domain: domain,
    origin_ip: `185.${seed % 255}.${(seed * 7) % 255}.${(seed * 13) % 254 + 1}`,
    spf_status: seed % 2 === 0 ? 'fail' : 'pass',
    dkim_status: seed % 3 === 0 ? 'fail' : 'pass',
    dmarc_status: seed % 2 === 0 ? 'fail' : 'pass',
    extracted_urls: [`http://${domain}/verify`, `https://${domain}/login`].slice(0, 1 + (seed % 2)),
    email_body_text:
      `Parsed from uploaded file "${file?.name}". Urgent notice: your account shows unusual sign-in activity. ` +
      'Verify your identity immediately to avoid suspension.',
    ip_geolocation: { country, asn: `AS${10000 + (seed % 80000)} UnknownHost`, lat, lon },
    domain_age_days: (seed % 55) + 3,
    threat_intel_flags: flags,
    ai_nlp_intent: intents[seed % intents.length],
    ai_risk_score: risk,
    analysis_id: `analysis_${Date.now()}`,
    timestamp: new Date().toISOString(),
  }
}

/* ------------------------------------------------------------------ */
/* Case management — GET /api/cases with mock fallback                */
/* ------------------------------------------------------------------ */

const MOCK_CASES = [
  {
    id: 'case_001',
    title: 'Microsoft Impersonation Campaign',
    risk_level: 'critical',
    risk_score: 92.5,
    created_at: '2026-08-29T14:30:22Z',
    email_count: 3,
    status: 'investigating',
  },
  {
    id: 'case_002',
    title: 'Invoice Fraud — Finance Dept',
    risk_level: 'high',
    risk_score: 78.3,
    created_at: '2026-08-28T09:15:00Z',
    email_count: 1,
    status: 'resolved',
  },
  {
    id: 'case_003',
    title: 'HR Phishing Campaign',
    risk_level: 'medium',
    risk_score: 45.2,
    created_at: '2026-08-27T16:42:10Z',
    email_count: 5,
    status: 'monitoring',
  },
]

export async function getCases() {
  if (await checkHealth()) {
    try {
      const res = await fetch(`${API_BASE}/cases`)
      if (res.ok) {
        const data = await res.json()
        // Backend returns { cases: [...] } with full case objects
        // Frontend expects array with id, title, risk_level, risk_score, created_at, email_count, status
        return (data.cases || []).map(c => ({
          id: c.case_id,
          title: c.subject || 'No Subject',
          risk_level: c.risk_level?.toLowerCase() || 'low',
          risk_score: c.risk_score || 0,
          created_at: c.updated_at || c.created_at,
          email_count: 1,
          status: c.classification === 'malicious' ? 'investigating' : 'monitoring',
        }))
      }
    } catch {
      /* fall through to mock */
    }
  }
  await new Promise((r) => setTimeout(r, 250))
  return MOCK_CASES
}

const riskLevel = (score) =>
  score >= 75 ? 'critical' : score >= 45 ? 'high' : score >= 25 ? 'medium' : 'low'

/**
 * Create a case from a finished analysis.
 * Note: Backend auto-creates cases on analysis, so this creates a local mock case.
 * The analysis is already saved as a case by the backend.
 */
export async function createCase(analysis) {
  const payload = {
    title: `${analysis.ai_nlp_intent} — ${analysis.sender_domain}`,
    risk_level: riskLevel(analysis.ai_risk_score),
    risk_score: analysis.ai_risk_score,
    status: 'investigating',
    email_count: 1,
    analysis_id: analysis.analysis_id,
    message_id: analysis.message_id,
  }
  
  // Backend doesn't have POST /api/cases - cases are created during analysis
  // Return a mock case locally
  await new Promise((r) => setTimeout(r, 200))
  return { id: `case_${Date.now()}`, created_at: new Date().toISOString(), ...payload }
}

/** Download the current analysis as a JSON forensic report. */
export function exportReportJson(analysis) {
  const blob = new Blob([JSON.stringify(analysis, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `forensic_report_${analysis.analysis_id ?? Date.now()}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/** Fetch full case report by ID from backend */
export async function getCaseById(caseId) {
  if (await checkHealth()) {
    try {
      const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseId)}`)
      if (res.ok) return await res.json()
    } catch {
      /* fall through */
    }
  }
  return null
}

/** Fetch dashboard stats from backend */
export async function getDashboardStats() {
  if (await checkHealth()) {
    try {
      const res = await fetch(`${API_BASE}/dashboard/stats`)
      if (res.ok) return await res.json()
    } catch {
      /* fall through */
    }
  }
  return { total_cases: 0, average_risk_score: 0, by_risk_level: {} }
}

/** Fetch campaign graph from backend */
export async function getCampaignGraph() {
  if (await checkHealth()) {
    try {
      const res = await fetch(`${API_BASE}/graph/campaigns`)
      if (res.ok) return await res.json()
    } catch {
      /* fall through */
    }
  }
  return { campaigns: [], total_cases: 0 }
}

/** Fetch graph for a specific case from backend */
export async function getCaseGraph(caseId) {
  if (await checkHealth()) {
    try {
      const res = await fetch(`${API_BASE}/graph/${encodeURIComponent(caseId)}`)
      if (res.ok) return await res.json()
    } catch {
      /* fall through */
    }
  }
  return { nodes: [], edges: [] }
}