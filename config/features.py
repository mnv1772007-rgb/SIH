"""
ml/config/features.py - Feature configuration for ML pipeline
Author: BTech Cyber Security Student
"""

FEATURE_CONFIG = {
    "text_features": {
        "tfidf_max_features": 5000,          # Reduced for student project
        "tfidf_ngram_range": [1, 2],
        "embedding_model": "all-MiniLM-L6-v2",  # Lightweight SBERT
        "readability_metrics": True,
    },
    "metadata_features": {
        "auth_spf_dkim_dmarc": True,
        "header_consistency": True,
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
    },
    "behavioral_features": {
        "display_name_embedding": True,
        "urgency_keywords": True,
        "financial_keywords": True,
        "credential_keywords": True,
    },
    "structural_features": {
        "html_ratio": True,
        "attachment_count": True,
        "executable_attachment": True,
        "url_count": True,
        "url_entropy": True,
        "punycode_domains": True,
        "ip_based_urls": True,
    },
    "risk_scoring": {
        "max_tally": 100,
        "risk_thresholds": {
            "minimal": 0,
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 100,
        }
    }
}