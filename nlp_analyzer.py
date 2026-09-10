"""
Role 2: AI / NLP / ML Threat Detection Engine
Analyzes email content for phishing, BEC, fraud, and impersonation patterns.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ThreatClassification(Enum):
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    FRAUD_RELATED = "fraud_related"
    BEC_LIKE = "bec_like"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCALIBRATED = "uncalibrated"


@dataclass
class NLPFinding:
    finding_id: str
    type: str
    severity: str
    message: str
    evidence: str
    confidence: str
    category: str  # OBSERVED, DERIVED, INFERRED
    limitations: List[str]


# ============================================================
# LEXICONS / PATTERNS
# ============================================================

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediate\b", r"\basap\b", r"\bright away\b",
    r"\bact now\b", r"\btime.sensitive\b", r"\bdeadline\b", r"\bexpire\b",
    r"\blast chance\b", r"\bhurry\b", r"\bquickly\b", r"\bpromptly\b"
]

FEAR_PRESSURE_PATTERNS = [
    r"\bsuspend\b", r"\bterminate\b", r"\bclose\b", r"\block\b",
    r"\bfreeze\b", r"\bdisable\b", r"\brevoke\b", r"\bpenalt\b",
    r"\blegal action\b", r"\blawsuit\b", r"\bconsequence\b", r"\brisk\b",
    r"\bthreat\b", r"\bwarning\b", r"\balert\b", r"\bcritical\b"
]

CREDENTIAL_REQUEST_PATTERNS = [
    r"\bpassword\b", r"\bpasscode\b", r"\bpin\b", r"\bcredential\b",
    r"\blogin\b", r"\bsign.?in\b", r"\busername\b", r"\buser.?id\b",
    r"\bverify.?account\b", r"\bconfirm.?identity\b", r"\bauthenticate\b",
    r"\bsecurity.?question\b", r"\bsecret\b", r"\botp\b", r"\b2fa\b"
]

FINANCIAL_PATTERNS = [
    r"\bwire\b", r"\btransfer\b", r"\bbank.?detail\b", r"\baccount.?number\b",
    r"\brouting\b", r"\bswift\b", r"\biban\b", r"\bpayment\b",
    r"\binvoice\b", r"\bpayroll\b", r"\bsalary\b", r"\bcompensation\b",
    r"\bbonus\b", r"\breimburse\b", r"\bexpense\b", r"\bvendor\b",
    r"\bsupplier\b", r"\bchange.?detail\b", r"\bupdate.?payment\b",
    r"\bgift.?card\b", r"\bcrypto\b", r"\bbitcoin\b", r"\bethereum\b"
]

EXECUTIVE_IMPERSONATION_PATTERNS = [
    r"\bceo\b", r"\bcfo\b", r"\bcto\b", r"\bcoo\b", r"\bpresident\b",
    r"\bvice.?president\b", r"\bvp\b", r"\bdirector\b", r"\bmanager\b",
    r"\bhead.?of\b", r"\bchief\b", r"\bfounder\b", r"\bowner\b",
    r"\bboard\b", r"\bchairman\b", r"\bexecutive\b"
]

SOCIAL_ENGINEERING_PATTERNS = [
    r"\bverify\b", r"\bvalidate\b", r"\bconfirm\b", r"\bupdate\b",
    r"\bupgrade\b", r"\brenew\b", r"\breactivate\b", r"\bunlock\b",
    r"\brecover\b", r"\breset\b", r"\benable\b", r"\bauthorize\b"
]

CALL_TO_ACTION_PATTERNS = [
    r"\bclick\b", r"\blink\b", r"\bbutton\b", r"\bdownload\b",
    r"\battachment\b", r"\breply\b", r"\brespond\b", r"\bcall\b",
    r"\bcontact\b", r"\bvisit\b", r"\bgo to\b", r"\baccess\b"
]

# Suspicious sender patterns
GENERIC_SENDER_PATTERNS = [
    r"^noreply@", r"^no.?reply@", r"^admin@", r"^support@",
    r"^info@", r"^help@", r"^service@", r"^billing@",
    r"^security@", r"^alert@", r"^notification@"
]

# Domain similarity (basic)
TYPOQUATTING_PATTERNS = [
    r"[aeiou]{2,}",  # vowel repetition
    r"[bcdfghjklmnpqrstvwxyz]{3,}",  # consonant clusters
]

# HTML deception patterns
HTML_DECEPTION_PATTERNS = [
    r"style\s*=\s*[\"']display\s*:\s*none",
    r"style\s*=\s*[\"']visibility\s*:\s*hidden",
    r"font.size\s*:\s*0",
    r"color\s*:\s*transparent",
    r"opacity\s*:\s*0",
    r"width\s*:\s*0",
    r"height\s*:\s*0",
    r"position\s*:\s*absolute",
    r"z.index\s*:\s*-",
]


def extract_text_features(text: str) -> Dict[str, Any]:
    """Extract linguistic features from email text."""
    text_lower = text.lower()
    word_count = len(text.split())
    
    features = {
        "word_count": word_count,
        "char_count": len(text),
        "urgency_score": 0,
        "fear_pressure_score": 0,
        "credential_request_score": 0,
        "financial_score": 0,
        "executive_impersonation_score": 0,
        "social_engineering_score": 0,
        "call_to_action_score": 0,
        "matched_patterns": {}
    }
    
    for pattern in URGENCY_PATTERNS:
        matches = len(re.findall(pattern, text_lower))
        if matches:
            features["urgency_score"] += matches
            features["matched_patterns"][f"urgency:{pattern}"] = matches
    
    for pattern in FEAR_PRESSURE_PATTERNS:
        matches = len(re.findall(pattern, text_lower))
        if matches:
            features["fear_pressure_score"] += matches
            features["matched_patterns"][f"fear:{pattern}"] = matches
    
    for pattern in CREDENTIAL_REQUEST_PATTERNS:
        matches = len(re.findall(pattern, text_lower))
        if matches:
            features["credential_request_score"] += matches
            features["matched_patterns"][f"credential:{pattern}"] = matches
    
    for pattern in FINANCIAL_PATTERNS:
        matches = len(re.findall(pattern, text_lower))
        if matches:
            features["financial_score"] += matches
            features["matched_patterns"][f"financial:{pattern}"] = matches
    
    for pattern in EXECUTIVE_IMPERSONATION_PATTERNS:
        matches = len(re.findall(pattern, text_lower))
        if matches:
            features["executive_impersonation_score"] += matches
            features["matched_patterns"][f"executive:{pattern}"] = matches
    
    for pattern in SOCIAL_ENGINEERING_PATTERNS:
        matches = len(re.findall(pattern, text_lower))
        if matches:
            features["social_engineering_score"] += matches
            features["matched_patterns"][f"social:{pattern}"] = matches
    
    for pattern in CALL_TO_ACTION_PATTERNS:
        matches = len(re.findall(pattern, text_lower))
        if matches:
            features["call_to_action_score"] += matches
            features["matched_patterns"][f"cta:{pattern}"] = matches
    
    return features


def analyze_sender_impersonation(email_data: Dict) -> List[NLPFinding]:
    """Analyze sender for impersonation indicators."""
    findings = []
    
    from_addr = email_data.get("from", "")
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")
    
    # Extract display name and email
    display_name = ""
    email_address = ""
    if from_addr:
        import email.utils
        display_name, email_address = email.utils.parseaddr(from_addr)
    
    # Check for executive display name with generic/mismatched email
    if display_name:
        display_lower = display_name.lower()
        for pattern in EXECUTIVE_IMPERSONATION_PATTERNS:
            if re.search(pattern, display_lower):
                # Check if email domain is suspicious
                if email_address:
                    domain = email_address.split("@")[-1].lower() if "@" in email_address else ""
                    # Check for free email providers or mismatched domains
                    free_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com"}
                    if domain in free_providers:
                        findings.append(NLPFinding(
                            finding_id=f"impersonation_executive_free_{hash(display_name) % 10000}",
                            type="executive_impersonation_free_provider",
                            severity="high",
                            message=f"Display name suggests executive role ('{display_name}') but sent from free email provider ({domain})",
                            evidence=f"From: {from_addr}",
                            confidence="high",
                            category="OBSERVED",
                            limitations=["Display name can be set arbitrarily; requires additional context"]
                        ))
    
    # Check Reply-To mismatch with From
    if reply_to and from_addr:
        from_domain = email_address.split("@")[-1].lower() if "@" in email_address else ""
        reply_display, reply_email = email.utils.parseaddr(reply_to)
        reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""
        
        if from_domain and reply_domain and from_domain != reply_domain:
            findings.append(NLPFinding(
                finding_id=f"impersonation_reply_mismatch_{hash(reply_to) % 10000}",
                type="reply_to_domain_mismatch",
                severity="medium",
                message=f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
                evidence=f"From: {from_addr}, Reply-To: {reply_to}",
                confidence="high",
                category="OBSERVED",
                limitations=["Legitimate forwarding services may cause this"]
            ))
    
    # Check Return-Path mismatch
    if return_path and from_addr:
        return_email = return_path.strip("<>")
        return_domain = return_email.split("@")[-1].lower() if "@" in return_email else ""
        from_domain = email_address.split("@")[-1].lower() if "@" in email_address else ""
        
        if from_domain and return_domain and from_domain != return_domain:
            findings.append(NLPFinding(
                finding_id=f"impersonation_return_mismatch_{hash(return_path) % 10000}",
                type="return_path_domain_mismatch",
                severity="medium",
                message=f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})",
                evidence=f"From: {from_addr}, Return-Path: {return_path}",
                confidence="high",
                category="OBSERVED",
                limitations=["Mailing lists and ESPs commonly rewrite Return-Path"]
            ))
    
    return findings


def analyze_phishing_language(text: str, subject: str = "") -> List[NLPFinding]:
    """Analyze email text for phishing language patterns."""
    findings = []
    full_text = f"{subject} {text}"
    features = extract_text_features(full_text)
    
    # High urgency + credential request = strong phishing signal
    if features["urgency_score"] >= 2 and features["credential_request_score"] >= 1:
        findings.append(NLPFinding(
            finding_id=f"phishing_urgency_credential_{hash(full_text[:50]) % 10000}",
            type="phishing_urgency_credential_harvest",
            severity="high",
            message="Email combines urgent language with credential requests - classic phishing pattern",
            evidence=f"Urgency indicators: {features['urgency_score']}, Credential requests: {features['credential_request_score']}",
            confidence="high",
            category="INFERRED",
            limitations=["Keywords alone don't confirm phishing; context matters"]
        ))
    
    # Fear/pressure + call to action
    if features["fear_pressure_score"] >= 2 and features["call_to_action_score"] >= 1:
        findings.append(NLPFinding(
            finding_id=f"phishing_fear_cta_{hash(full_text[:50]) % 10000}",
            type="phishing_fear_pressure_action",
            severity="high",
            message="Email uses fear/pressure tactics with explicit call-to-action",
            evidence=f"Fear indicators: {features['fear_pressure_score']}, CTA indicators: {features['call_to_action_score']}",
            confidence="high",
            category="INFERRED",
            limitations=["Legitimate security alerts may use similar language"]
        ))
    
    # Financial + executive impersonation = BEC indicator
    if features["financial_score"] >= 1 and features["executive_impersonation_score"] >= 1:
        findings.append(NLPFinding(
            finding_id=f"bec_financial_executive_{hash(full_text[:50]) % 10000}",
            type="bec_financial_executive_impersonation",
            severity="high",
            message="Email references financial actions with executive authority language - potential BEC",
            evidence=f"Financial terms: {features['financial_score']}, Executive terms: {features['executive_impersonation_score']}",
            confidence="medium",
            category="INFERRED",
            limitations=["Legitimate executive communications may discuss finances"]
        ))
    
    # Generic sender with credential request
    if features["credential_request_score"] >= 2:
        findings.append(NLPFinding(
            finding_id=f"phishing_credential_heavy_{hash(full_text[:50]) % 10000}",
            type="phishing_heavy_credential_requests",
            severity="medium",
            message="Email contains multiple credential-related requests",
            evidence=f"Credential request indicators: {features['credential_request_score']}",
            confidence="medium",
            category="OBSERVED",
            limitations=["Legitimate account recovery emails may request credentials"]
        ))
    
    # Social engineering language
    if features["social_engineering_score"] >= 3:
        findings.append(NLPFinding(
            finding_id=f"phishing_social_eng_{hash(full_text[:50]) % 10000}",
            type="phishing_social_engineering_language",
            severity="medium",
            message="Email uses multiple social engineering persuasion patterns",
            evidence=f"Social engineering indicators: {features['social_engineering_score']}",
            confidence="medium",
            category="OBSERVED",
            limitations=["Marketing and legitimate emails may use persuasive language"]
        ))
    
    return findings


def analyze_bec_patterns(email_data: Dict, text: str) -> List[NLPFinding]:
    """Analyze for Business Email Compromise patterns."""
    findings = []
    features = extract_text_features(text)
    
    # Payment diversion / bank detail change
    payment_change_keywords = [
        "change.*bank", "update.*bank", "new.*account", "different.*account",
        "wire.*to", "send.*to", "payment.*detail", "bank.*detail"
    ]
    
    for kw in payment_change_keywords:
        if re.search(kw, text, re.IGNORECASE):
            findings.append(NLPFinding(
                finding_id=f"bec_payment_change_{hash(kw) % 10000}",
                type="bec_payment_diversion",
                severity="high",
                message="Email requests changes to payment/bank details - potential BEC",
                evidence=f"Matched pattern: {kw}",
                confidence="high",
                category="OBSERVED",
                limitations=["Legitimate vendor communications may update payment details"]
            ))
    
    # Gift card requests
    if re.search(r"gift.?card", text, re.IGNORECASE):
        findings.append(NLPFinding(
            finding_id=f"bec_gift_card_{hash(text[:50]) % 10000}",
            type="bec_gift_card_request",
            severity="high",
            message="Email requests gift cards - common BEC tactic",
            evidence="Gift card request detected in email body",
            confidence="high",
            category="OBSERVED",
            limitations=["Rare but possible legitimate use cases exist"]
        ))
    
    # Payroll manipulation
    payroll_keywords = ["payroll", "direct deposit", "salary", "wages", "compensation"]
    for kw in payroll_keywords:
        if re.search(kw, text, re.IGNORECASE) and features["financial_score"] > 0:
            findings.append(NLPFinding(
                finding_id=f"bec_payroll_{hash(kw) % 10000}",
                type="bec_payroll_manipulation",
                severity="medium",
                message=f"Email references payroll/compensation changes - potential BEC",
                evidence=f"Matched: {kw}",
                confidence="medium",
                category="INFERRED",
                limitations=["HR communications legitimately discuss payroll"]
            ))
    
    return findings


def analyze_html_deception(html_body: str) -> List[NLPFinding]:
    """Analyze HTML for deception techniques."""
    findings = []
    
    if not html_body:
        return findings
    
    html_lower = html_body.lower()
    
    # Hidden text/elements
    for pattern in HTML_DECEPTION_PATTERNS:
        if re.search(pattern, html_lower):
            findings.append(NLPFinding(
                finding_id=f"html_deception_{hash(pattern) % 10000}",
                type="html_hidden_content",
                severity="medium",
                message="HTML contains hidden/deceptive styling that may conceal malicious content",
                evidence=f"Matched pattern: {pattern}",
                confidence="medium",
                category="OBSERVED",
                limitations=["Some legitimate emails use conditional styling"]
            ))
    
    # Forms in email (phishing)
    if re.search(r"<form[^>]*>", html_lower):
        findings.append(NLPFinding(
            finding_id=f"html_form_{hash(html_body[:50]) % 10000}",
            type="html_form_in_email",
            severity="high",
            message="Email contains HTML form - potential credential harvesting",
            evidence="<form> tag detected in email HTML",
            confidence="high",
            category="OBSERVED",
            limitations=["Legitimate newsletters may have subscription forms"]
        ))
    
    # Iframes
    if re.search(r"<iframe[^>]*>", html_lower):
        findings.append(NLPFinding(
            finding_id=f"html_iframe_{hash(html_body[:50]) % 10000}",
            type="html_iframe_in_email",
            severity="high",
            message="Email contains iframe - potential malicious content loading",
            evidence="<iframe> tag detected in email HTML",
            confidence="high",
            category="OBSERVED",
            limitations=["Rare legitimate use cases"]
        ))
    
    return findings


def classify_email(findings: List[NLPFinding]) -> Dict[str, Any]:
    """
    Classify email based on findings.
    Returns classification with confidence and reasoning.
    """
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    finding_types = set()
    
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        finding_types.add(f.type)
    
    # Heuristic classification (NOT calibrated probability)
    if severity_counts["high"] >= 2:
        classification = ThreatClassification.PHISHING.value
        confidence = ConfidenceLevel.HIGH.value
    elif severity_counts["high"] >= 1 and severity_counts["medium"] >= 2:
        classification = ThreatClassification.SUSPICIOUS.value
        confidence = ConfidenceLevel.MEDIUM.value
    elif severity_counts["high"] >= 1:
        classification = ThreatClassification.SUSPICIOUS.value
        confidence = ConfidenceLevel.MEDIUM.value
    elif severity_counts["medium"] >= 2:
        classification = ThreatClassification.SUSPICIOUS.value
        confidence = ConfidenceLevel.LOW.value
    elif severity_counts["medium"] >= 1:
        classification = ThreatClassification.SUSPICIOUS.value
        confidence = ConfidenceLevel.LOW.value
    else:
        classification = ThreatClassification.LEGITIMATE.value
        confidence = ConfidenceLevel.LOW.value
    
    # Check for specific subtypes
    if any("bec_" in ft for ft in finding_types):
        classification = ThreatClassification.BEC_LIKE.value
    elif any("impersonation_" in ft for ft in finding_types):
        classification = ThreatClassification.IMPERSONATION.value
    elif any("fraud_" in ft for ft in finding_types):
        classification = ThreatClassification.FRAUD_RELATED.value
    
    return {
        "classification": classification,
        "confidence": confidence,
        "reasoning": {
            "high_severity_findings": severity_counts["high"],
            "medium_severity_findings": severity_counts["medium"],
            "finding_types": list(finding_types),
            "note": "Heuristic classification based on pattern matching. Not a calibrated probability. Requires human analyst review."
        }
    }


def analyze_email_nlp(email_data: Dict, body_text: str, html_body: str = "", subject: str = "") -> Dict[str, Any]:
    """
    Main NLP analysis entry point.
    Returns all findings and classification.
    """
    all_findings = []
    
    # 1. Sender impersonation analysis
    all_findings.extend(analyze_sender_impersonation(email_data))
    
    # 2. Phishing language analysis
    all_findings.extend(analyze_phishing_language(body_text, subject))
    
    # 3. BEC pattern analysis
    all_findings.extend(analyze_bec_patterns(email_data, body_text))
    
    # 4. HTML deception analysis
    all_findings.extend(analyze_html_deception(html_body))
    
    # 5. Classification
    classification = classify_email(all_findings)
    
    # Convert findings to serializable format
    findings_output = []
    for f in all_findings:
        findings_output.append({
            "finding_id": f.finding_id,
            "type": f.type,
            "severity": f.severity,
            "message": f.message,
            "evidence": f.evidence,
            "confidence": f.confidence,
            "category": f.category,
            "limitations": f.limitations
        })
    
    return {
        "nlp_findings": findings_output,
        "classification": classification,
        "feature_summary": extract_text_features(f"{subject} {body_text}"),
        "engine_version": "1.0.0",
        "note": "NLP analysis based on pattern matching heuristics. Not ML-based. Results are supporting evidence only."
    }


if __name__ == "__main__":
    # Test with sample email
    test_email = {
        "from": "CEO John Smith <ceo@company.com>",
        "reply_to": "ceo@personal-gmail.com",
        "return_path": "<ceo@company.com>"
    }
    
    test_body = """
    Urgent: I need you to process a wire transfer immediately.
    Our vendor has changed their bank details. Please update the payment
    to the new account number. This is time sensitive and must be done today.
    Confirm once completed.
    """
    
    result = analyze_email_nlp(test_email, test_body, subject="Urgent Wire Transfer")
    
    import json
    print(json.dumps(result, indent=2))