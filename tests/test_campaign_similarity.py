from app.services.campaign_clustering import campaign_clustering


def test_similar_emails_produce_high_similarity():
    email1 = {
        "email_id": "email-001",
        "subject": "Urgent Verify Account",
        "sender": "sec@evil-domain.com",
        "sender_domain": "evil-domain.com",
        "timestamp": "2026-09-10T08:00:00Z",
        "domains": ["evil-domain.com", "phish-cdn.net"],
        "ips": ["198.51.100.25"],
        "urls": ["https://phish-cdn.net/login"],
        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "classification": "phishing",
    }

    email2 = {
        "email_id": "email-002",
        "subject": "Action Required Verify Account",
        "sender": "admin@evil-domain.com",
        "sender_domain": "evil-domain.com",
        "timestamp": "2026-09-10T08:20:00Z",
        "domains": ["evil-domain.com", "phish-cdn.net"],
        "ips": ["198.51.100.25"],
        "urls": ["https://phish-cdn.net/login"],
        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "classification": "phishing",
    }

    score, breakdown = campaign_clustering.compute_similarity(email1, email2)
    assert score >= 0.70
    assert "198.51.100.25" in breakdown["shared_ips"]
    assert "phish-cdn.net" in breakdown["shared_domains"]


def test_unrelated_email_produces_low_similarity():
    phishing_email = {
        "email_id": "email-001",
        "subject": "Urgent Verify Account",
        "sender": "sec@evil-domain.com",
        "sender_domain": "evil-domain.com",
        "timestamp": "2026-09-10T08:00:00Z",
        "domains": ["evil-domain.com"],
        "ips": ["198.51.100.25"],
        "urls": ["https://phish-cdn.net/login"],
        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "classification": "phishing",
    }

    benign_newsletter = {
        "email_id": "email-unrelated",
        "subject": "Monthly Engineering Updates",
        "sender": "news@tech-digest.org",
        "sender_domain": "tech-digest.org",
        "timestamp": "2026-09-10T04:00:00Z",
        "domains": ["tech-digest.org"],
        "ips": ["203.0.113.88"],
        "urls": ["https://tech-digest.org/blog"],
        "hashes": ["4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"],
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "classification": "benign",
    }

    score, breakdown = campaign_clustering.compute_similarity(phishing_email, benign_newsletter)
    assert score < 0.25
    assert len(breakdown["shared_ips"]) == 0
    assert len(breakdown["shared_domains"]) == 0
