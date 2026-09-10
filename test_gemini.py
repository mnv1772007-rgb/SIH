"""Quick test: Gemini API connectivity and response format."""
import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

key = os.getenv("GEMINI_API_KEY", "")
model = "gemini-3.6-flash"

prompt = (
    "You are a cybersecurity email threat analyst. "
    "Analyze the evidence and return ONLY a JSON object with these exact fields: "
    "classification (phishing/bec/malware/suspicious/benign), risk_score (0-100), "
    "confidence (0.0-1.0), executive_summary (string), attack_hypothesis (string), "
    "recommended_actions (list of strings). "
    "Evidence: From=security@paypa1.com, SPF=fail, DKIM=fail, DMARC=fail, "
    "Sending IP=45.142.212.100 (AE), URLs=2, Risk Signals=SPF FAIL, Typosquatting."
)

url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
res = requests.post(
    url,
    headers={"Content-Type": "application/json"},
    json={
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    },
    timeout=30,
)

print(f"Status: {res.status_code}")
if res.status_code == 200:
    text = res.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
    print(f"Response:\n{text[:600]}")
    try:
        parsed = json.loads(text)
        print(f"\nParsed OK: classification={parsed.get('classification')}, risk_score={parsed.get('risk_score')}")
    except Exception as e:
        print(f"\nJSON parse error: {e}")
else:
    print(f"Error: {res.text[:400]}")
