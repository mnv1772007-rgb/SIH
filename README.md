# Module 3: Threat Intelligence & Data Platform
### SIH Problem Statement 26106: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence

A production-ready, fail-soft threat intelligence enrichment and passive indicator correlation engine.

---

## Architecture Overview

```
Email-Threat-Forensics/
├── main.py                     # Standalone FastAPI service & CLI runner
├── threat_intel/               # Core Threat Intelligence Module
│   ├── __init__.py             # Public module interface
│   ├── schema.py               # Canonical normalized result schema & provenance
│   ├── normalizer.py           # IOC normalization (IP, Domain, URL, Hash, Email)
│   ├── cache.py                # In-memory adaptive TTL cache
│   ├── aggregator.py           # Multi-provider consensus aggregator
│   ├── service.py              # Thread-pool orchestrator for batch & single IOCs
│   └── providers/              # External intelligence provider adapters
│       ├── __init__.py         # Provider lookup registry
│       ├── base.py             # Resilient HTTP sessions, retries, and error classifier
│       ├── virustotal.py       # VirusTotal v3 (IP, domain, URL report, hash)
│       ├── abuseipdb.py        # AbuseIPDB v2 (IP reputation)
│       ├── urlhaus.py          # URLhaus (Malware URL and domain lookups)
│       ├── phishtank.py        # PhishTank (Opt-in phishing verification)
│       ├── otx.py              # AlienVault OTX community threat pulses
│       ├── greynoise.py        # GreyNoise internet scanner classification
│       └── urlscan.py          # URLScan historical passive search
├── tests/
│   └── test_threat_intel.py    # Comprehensive test suite (26 unit & API tests)
├── .env.example                # Template for threat intelligence API keys
├── requirements.txt            # Python dependencies
└── CREDENTIAL_AUDIT.md         # Credential security & audit documentation
```

---

## Key Features

1. **Passive Lookups Only:**
   - No URLs or files are executed, browsed, or submitted.
   - VirusTotal queries existing reports via URL hash identifiers.
   - URLScan performs historical searches without dispatching live crawlers.
   - PhishTank includes double opt-in protection (`PHISHTANK_ENABLED=true`).

2. **Consensus & Provenance:**
   - Multi-source corroboration calculates weighted confidence.
   - Every provider's raw status, response code, and latency are preserved in the `provenance` array.
   - Absence of intelligence is never treated as a clean verdict (`unknown` verdict on unconfigured/unavailable).

3. **Adaptive Caching:**
   - High TTL (1 hour) for successful threat/clean records.
   - Short TTL (2 minutes) for rate limits and temporary network errors to allow fast recovery.

4. **Network & Infrastructure Attribution:**
   - Geolocation and ASN details are clearly categorized as network infrastructure, preventing false attribution to physical attackers.

---

## Setup & Configuration

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure API Keys:**
   Copy `.env.example` to `.env` and fill in your keys:
   ```bash
   THREAT_INTELLIGENCE_ENABLED=true
   VIRUSTOTAL_API_KEY=your_key
   ABUSEIPDB_API_KEY=your_key
   URLHAUS_AUTH_KEY=your_key
   OTX_API_KEY=your_key
   GREYNOISE_API_KEY=your_key
   URLSCAN_API_KEY=your_key
   PHISHTANK_API_KEY=your_key
   PHISHTANK_ENABLED=false
   ```

---

## Running the Service

Start the FastAPI microservice:
```bash
python main.py
```
Or with uvicorn:
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

---

## API Endpoints

- **Health Check:** `GET /health`
- **Single Indicator Lookup:** `POST /api/threat-intel/lookup`
  ```json
  {
    "indicator": "8.8.8.8",
    "ioc_type": "ip",
    "force_refresh": false
  }
  ```
- **Batch Indicator Lookup:** `POST /api/threat-intel/batch`
  ```json
  {
    "indicators": [
      {"value": "1.1.1.1", "type": "ip"},
      {"value": "example.com", "type": "domain"}
    ],
    "force_refresh": false
  }
  ```
- **Cache Statistics:** `GET /api/threat-intel/cache/stats`

---

## Running Tests

Run the complete test suite:
```bash
pytest tests/
```
Or via Python's standard unittest:
```bash
python -m unittest discover tests
```
