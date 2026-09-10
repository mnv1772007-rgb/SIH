"""
ml/ — Email Threat Detection ML Package
Role 2: AI/ML Detection Layer

Quick start:
    from ml.serve.predict import predict_email_threat

    result = predict_email_threat({
        "subject": "Urgent: Verify your account",
        "body": "Click here: http://evil.com/verify",
        "sender": "admin@evil.com",
        "spf": "fail",
        "dkim": "fail",
    })
    print(result["risk"]["level"])  # 'HIGH' or 'CRITICAL'
"""