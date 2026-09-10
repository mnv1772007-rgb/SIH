# ================================
# ROLE 4 - GRAPH SCHEMA
# ================================

NODE_TYPES = {
    "EMAIL": "Email",
    "EMAIL_ADDRESS": "EmailAddress",
    "SENDER": "Sender",
    "REPLY_TO": "ReplyTo",
    "URL": "URL",
    "DOMAIN": "Domain",
    "IP": "IP",
    "ATTACHMENT": "Attachment",
    "MAIL_SERVER": "MailServer",
    "RELAY_HOP": "RelayHop",
    "GEOLOCATION": "Geolocation",
    "THREAT_INTEL": "ThreatIntel",
    "CASE": "Case",
    "CAMPAIGN_CLUSTER": "CampaignCluster"
}


RELATIONSHIPS = {
    "SENT_BY": "SENT_BY",
    "SENT_TO": "SENT_TO",
    "REPLY_TO": "REPLY_TO",
    "CONTAINS_URL": "CONTAINS_URL",
    "CONTAINS_DOMAIN": "CONTAINS_DOMAIN",
    "CONTAINS_IP": "CONTAINS_IP",
    "HAS_ATTACHMENT": "HAS_ATTACHMENT",
    "RESOLVES_TO": "RESOLVES_TO",
    "SENT_FROM": "SENT_FROM",
    "RECEIVED_BY": "RECEIVED_BY",
    "HOSTED_ON": "HOSTED_ON",
    "HAS_URL": "HAS_URL",
    "HAS_GEOLOCATION": "HAS_GEOLOCATION",
    "REPLIES_TO": "REPLIES_TO",
    "PART_OF_CAMPAIGN": "PART_OF_CAMPAIGN",
    "SHARES_INFRASTRUCTURE": "SHARES_INFRASTRUCTURE",
    "RELAYED_FROM": "RELAYED_FROM",
    "RELAYED_TO": "RELAYED_TO",
    "ENRICHED_BY": "ENRICHED_BY",
}


def show_schema():

    print("========== ROLE 4 GRAPH SCHEMA ==========")

    print("\n[+] Nodes")

    for key, value in NODE_TYPES.items():
        print(f"{key} -> {value}")

    print("\n[+] Relationships")

    for key, value in RELATIONSHIPS.items():
        print(f"{key} -> {value}")

    print("\n==========================================")


if __name__ == "__main__":

    show_schema()
