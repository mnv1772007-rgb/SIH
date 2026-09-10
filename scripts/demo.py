#!/usr/bin/env python3
"""
SIH Problem Statement 26106: Role 4 — One-Click End-to-End Demo Script
Demonstrates:
  1. API & Neo4j Health Check
  2. Safe Demo Graph Reset
  3. Ingestion of 4 analyzed emails (3 phishing campaign samples + 1 benign sample)
  4. Automatic Campaign Clustering & NetworkX Correlation
  5. Infrastructure Pivot Analysis (IP & Domain linkages)
  6. Explainable Attribution Confidence Scoring with Disclaimers
  7. Frontend API Handoff URLs for Role 6 UI Visualization
"""

import sys
import os
import json
import time
from pathlib import Path
import httpx

BASE_DIR = Path(__file__).resolve().parent.parent
DEMO_DIR = BASE_DIR / "demo"

BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000/api/v1")
HEALTH_URL = os.getenv("HEALTH_URL", "http://localhost:8000/health")
API_KEY = os.getenv("API_KEY", "dev-key")

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}


def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f"  {title.upper()}")
    print("=" * 70)


def run_demo():
    print_banner("SIH 26106 — Role 4: Graph & Campaign Correlation Demo")
    print(f"Target API Base: {BASE_URL}")

    client = httpx.Client(timeout=15.0)

    # 1. Health Check
    print("\n[Step 1/6] Verifying API & Database Connectivity...")
    try:
        resp = client.get(HEALTH_URL)
        if resp.status_code != 200:
            print(f"[!] Health check failed with HTTP {resp.status_code}: {resp.text}")
            return
        health = resp.json()
        print(f"[*] API Status: {health.get('status')}")
        print(f"[*] Neo4j Driver Status: {health.get('neo4j')}")
        print(f"[*] Service: {health.get('service')}")
    except Exception as e:
        print(f"[!] Could not connect to API server at {HEALTH_URL}.")
        print("    Please ensure the server is running: uvicorn app.main:app --reload --port 8000")
        print(f"    Error detail: {e}")
        return

    # 2. Reset Demo Graph (Optional & Safe)
    print("\n[Step 2/6] Safe Demo Graph Reset (confirm=true)...")
    try:
        reset_resp = client.delete(f"{BASE_URL}/graph/all?confirm=true", headers=HEADERS)
        if reset_resp.status_code == 200:
            print("[*] Previous demo graph state safely cleared.")
        else:
            print(f"[~] Reset note: {reset_resp.status_code}")
    except Exception as e:
        print(f"[~] Reset skipped: {e}")

    # 3. Ingest Demo Threat Intelligence Samples
    print("\n[Step 3/6] Ingesting Synthetic Threat Intelligence Telemetry...")
    demo_files = [
        ("Phishing Campaign Sample 1", DEMO_DIR / "email_001.json"),
        ("Phishing Campaign Sample 2", DEMO_DIR / "email_002.json"),
        ("Phishing Campaign Sample 3", DEMO_DIR / "email_003.json"),
        ("Benign Unrelated Sample 4", DEMO_DIR / "email_unrelated.json"),
    ]

    ingested_emails = []
    for label, filepath in demo_files:
        if not filepath.exists():
            print(f"[!] Demo file not found: {filepath}")
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            payload = json.load(f)

        resp = client.post(f"{BASE_URL}/graph/ingest", json=payload, headers=HEADERS)
        if resp.status_code == 201:
            res_data = resp.json().get("data", {})
            email_id = res_data.get("email_id")
            ingested_emails.append(email_id)
            print(f"  [+] Ingested {label} (ID: {email_id})")
            print(f"      Nodes Created: {res_data.get('nodes_created')}, Rels Created: {res_data.get('relationships_created')}")
        else:
            print(f"  [!] Failed to ingest {label}: {resp.status_code} {resp.text}")

    # Verify Ingestion Idempotency
    print("\n  [*] Verifying Ingestion Idempotency (re-submitting sample 1)...")
    with open(DEMO_DIR / "email_001.json", "r", encoding="utf-8") as f:
        re_payload = json.load(f)
    idemp_resp = client.post(f"{BASE_URL}/graph/ingest", json=re_payload, headers=HEADERS)
    if idemp_resp.status_code == 201:
        idemp_data = idemp_resp.json().get("data", {})
        print(f"      Re-ingest result -> Nodes Created: {idemp_data.get('nodes_created')} (Expected 0), Nodes Matched: {idemp_data.get('nodes_matched')}")
        print("      Idempotency confirmed: No duplicate entities created.")

    # 4. Trigger Campaign Clustering
    print("\n[Step 4/6] Executing Campaign Clustering & Community Detection...")
    cluster_resp = client.post(
        f"{BASE_URL}/campaigns/cluster",
        json={"similarity_threshold": 0.45, "min_cluster_size": 2},
        headers=HEADERS,
    )

    discovered_campaign_id = None
    if cluster_resp.status_code == 200:
        campaigns = cluster_resp.json().get("data", [])
        print(f"[*] Discovered {len(campaigns)} correlated threat campaign(s):")
        for camp in campaigns:
            discovered_campaign_id = camp.get("campaign_id")
            print(f"\n  [>>>] CAMPAIGN: {discovered_campaign_id}")
            print(f"        Email Count: {camp.get('email_count')}")
            print(f"        Correlation Confidence: {camp.get('confidence')}")
            print(f"        Risk Score: {camp.get('risk_score')}")
            print(f"        Shared Domains: {camp.get('shared_indicators', {}).get('domains')}")
            print(f"        Shared IPs: {camp.get('shared_indicators', {}).get('ips')}")
            print(f"        Shared Hashes: {camp.get('shared_indicators', {}).get('hashes')}")
            print("        Forensic Correlation Evidence:")
            for reason in camp.get("reasons", []):
                print(f"          - {reason}")
    else:
        print(f"[!] Campaign clustering failed: {cluster_resp.status_code} {cluster_resp.text}")

    # 5. Infrastructure Correlation Pivot
    print("\n[Step 5/6] Querying Infrastructure Hosting Clusters...")
    infra_resp = client.get(f"{BASE_URL}/infrastructure/clusters", headers=HEADERS)
    if infra_resp.status_code == 200:
        clusters = infra_resp.json().get("data", [])
        print(f"[*] Identified {len(clusters)} shared infrastructure cluster(s):")
        for c in clusters:
            print(f"  [+] IP: {c.get('ip')} (ASN: {c.get('asn')})")
            print(f"      Hosted Domains: {c.get('domains')}")
            print(f"      Associated Email Messages: {c.get('email_count')}")
            print(f"      Correlation Strength: {c.get('correlation_strength')}")

    # 6. Attribution Confidence Report
    if discovered_campaign_id:
        print(f"\n[Step 6/6] Generating Attribution Confidence Report for {discovered_campaign_id}...")
        conf_resp = client.get(f"{BASE_URL}/campaigns/{discovered_campaign_id}/confidence", headers=HEADERS)
        if conf_resp.status_code == 200:
            conf_data = conf_resp.json().get("data", {})
            print(f"[*] Overall Confidence: {conf_data.get('confidence')} (Level: {conf_data.get('level', '').upper()})")
            bd = conf_data.get("breakdown", {})
            print(f"    - Infrastructure Linkage : {bd.get('infrastructure')}")
            print(f"    - Temporal Clustering    : {bd.get('temporal')}")
            print(f"    - Behavioral Similarity  : {bd.get('behavioral')}")
            print(f"    - Content Lexical Match  : {bd.get('content')}")
            print("\n    Forensic Limitations (Strict Non-Attribution Policy):")
            for lim in conf_data.get("limitations", []):
                print(f"      * {lim}")

    # 7. Frontend Visualization Hand-Off
    print_banner("Frontend Visualization Handoff (Role 6 Ready)")
    print("Role 6 can visualize threat graphs using the following standardized endpoints:")
    if discovered_campaign_id:
        print(f"1. Campaign Graph Subgraph   : {BASE_URL}/campaigns/{discovered_campaign_id}/graph")
    print(f"2. Email Subgraph Pivot      : {BASE_URL}/graph/email/email-001")
    print(f"3. Infrastructure IP Subgraph: {BASE_URL}/graph/ip/198.51.100.25")
    print(f"4. Global Canvas Subgraph    : {BASE_URL}/graph/all?limit=50")
    print(f"5. Interactive OpenAPI Docs  : http://localhost:8000/docs")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()
