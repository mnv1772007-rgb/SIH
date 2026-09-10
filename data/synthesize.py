"""
ml/data/synthesize.py - Synthetic email dataset generator
Author: BTech Cyber Security Student

WARNING: This dataset is SYNTHETIC and is used ONLY for integration testing.
         Results trained on this data do NOT represent real-world model performance.

Fixed:
  - Syntax error on generate_balanced_dataset: 'n_ham: 2000' → 'n_ham: int = 2000'
  - Added random seed for reproducibility
  - Label 'ham' renamed to 'benign' to match project taxonomy
"""

import random
from typing import List, Dict, Optional

import pandas as pd
import numpy as np

# Try to import Faker for realistic synthetic data; fall back to simple generator
try:
    from faker import Faker
    _FAKER_AVAILABLE = True
    fake = Faker()
    Faker.seed(42)
except ImportError:
    _FAKER_AVAILABLE = False
    fake = None

random.seed(42)
np.random.seed(42)

# ---------------------------------------------------------------------------
# Template data
# ---------------------------------------------------------------------------

BEC_TEMPLATES = [
    "Hi {name}, I need you to process an urgent wire transfer of ${amount} to account {acct}. "
    "This is time-sensitive and confidential. Please confirm once done. - {ceo_name}",
    "Dear {name}, Please find attached the updated invoice #{inv_num} for ${amount}. "
    "Our banking details have changed. Use the new account: {new_acct}. Thanks, {vendor}",
    "Hello {name}, I've updated my direct deposit information. "
    "Please route my next paycheck to: {new_bank}. Thanks, {employee}",
    "Hi {name}, Quick request - can you purchase {count} gift cards for client gifts? "
    "I'll reimburse you. Need codes emailed back ASAP. - {manager}",
    "Hello {name}, We have a new vendor payment of ${amount} due today. "
    "Please use the updated banking details: {new_acct}. Urgent! - {finance}",
]

PHISHING_TEMPLATES = [
    "Congratulations! You've won ${amount}. Claim your prize now: {url}",
    "Your account will be suspended. Verify immediately: {url}",
    "Invoice #{inv} attached. Immediate payment required: {url}",
    "Package delivery failed. Reschedule here: {url}",
    "Tax refund available. Claim your ${amount} refund: {url}",
    "Your password expires in 24 hours. Reset here: {url}",
    "Suspicious login detected on your account. Verify identity: {url}",
]

SPAM_TEMPLATES = [
    "Buy {product} now! {discount}% off LIMITED TIME: {url}",
    "Best {product} deals this week. Click here: {url}",
    "Earn ${amount}/week from home! Details: {url}",
    "Cheap {product}. No prescription needed. Order now: {url}",
    "SALE! {discount}% off all {product}. Today only: {url}",
]

BENIGN_TEMPLATES = [
    "Hi {name}, here's the report you requested. Let me know if you need anything else.",
    "Thanks for the meeting today. Action items are attached.",
    "Please review the attached document and provide feedback by Friday.",
    "Meeting has been moved to {time}. Same conference room.",
    "Lunch at {place} today?",
    "Quick update on the project status - everything is on track for the deadline.",
    "Can you please review the attached proposal and share your thoughts?",
    "Following up on our conversation from yesterday. Please see attached.",
]

IMPERSONATION_URGENT_SUBJECTS = [
    "Security Alert", "Account Verification Required", "Urgent: Action Required",
    "Password Reset Needed", "Suspicious Login Attempt", "Verify Your Identity Now",
    "Account Suspended", "Security Notice",
]

SPOOFED_DISPLAY_NAMES = [
    "IT Support", "Security Team", "Administrator", "Help Desk",
    "Microsoft Support", "Google Security", "Amazon Support", "PayPal Security",
    "HR Department", "Finance Team", "CEO Office", "Legal Department",
]

TARGET_SERVICES = [
    "Microsoft 365", "Google Workspace", "AWS Console", "Azure Portal",
    "GitHub", "Slack", "Zoom", "Salesforce", "Workday", "Okta",
]

PRODUCTS = ["pills", "software", "watches", "sunglasses", "supplements", "electronics"]


def _rand_name() -> str:
    if _FAKER_AVAILABLE:
        return fake.name()
    names = ["Alice Johnson", "Bob Smith", "Carol White", "David Brown", "Eve Davis"]
    return random.choice(names)


def _rand_first() -> str:
    if _FAKER_AVAILABLE:
        return fake.first_name()
    return random.choice(["Alice", "Bob", "Carol", "Dave", "Eve"])


def _rand_email() -> str:
    if _FAKER_AVAILABLE:
        return fake.email()
    domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    return f"user{random.randint(1, 9999)}@{random.choice(domains)}"


def _rand_company() -> str:
    if _FAKER_AVAILABLE:
        return fake.company()
    companies = ["Acme Corp", "Global Tech", "Innovate Inc", "FastPay Ltd", "SecureBank"]
    return random.choice(companies)


def _rand_domain() -> str:
    if _FAKER_AVAILABLE:
        return fake.domain_name()
    tlds = [".com", ".net", ".org", ".info"]
    words = ["secure", "verify", "update", "login", "account", "bank", "service"]
    return random.choice(words) + str(random.randint(1, 999)) + random.choice(tlds)


def _rand_bban() -> str:
    return "".join([str(random.randint(0, 9)) for _ in range(12)])


def _rand_time() -> str:
    return f"{random.randint(9, 17)}:{random.choice(['00', '15', '30', '45'])} {'AM' if random.random() < 0.5 else 'PM'}"


def _rand_street() -> str:
    if _FAKER_AVAILABLE:
        return fake.street_name()
    return f"{random.randint(1, 99)} Main Street"


def _typosquat(domain: str) -> str:
    """Create a typosquatted version of a domain for impersonation samples."""
    strategies = [
        lambda d: d.replace(".", "-"),
        lambda d: d.replace("o", "0"),
        lambda d: d + "-security.com",
        lambda d: "security-" + d,
        lambda d: d.replace("l", "1"),
        lambda d: d.replace("i", "1"),
        lambda d: "www-" + d,
        lambda d: d.replace(".com", "") + ".net",
    ]
    return random.choice(strategies)(domain)


# ---------------------------------------------------------------------------
# Per-class generators
# ---------------------------------------------------------------------------

def generate_bec_samples(n: int) -> List[Dict]:
    """Generate synthetic BEC (Business Email Compromise) samples."""
    samples = []
    for _ in range(n):
        template = random.choice(BEC_TEMPLATES)
        amount = random.randint(5_000, 500_000)
        sender_email = _rand_email()
        reply_domain = _rand_domain()
        body = template.format(
            name=_rand_first(),
            amount=f"{amount:,}",
            acct=_rand_bban(),
            ceo_name=_rand_name(),
            inv_num=random.randint(100000, 999999),
            new_acct=_rand_bban(),
            vendor=_rand_company(),
            employee=_rand_name(),
            new_bank=_rand_company() + " Bank",
            count=random.randint(5, 50),
            manager=_rand_name(),
            finance=_rand_name(),
        )
        samples.append({
            "subject": f"Re: {random.choice(['Urgent Request', 'Payment Update', 'Wire Transfer', 'Invoice Update'])}",
            "body": body,
            "sender": f"{_rand_name()} <{sender_email}>",
            "reply_to": f"reply@{reply_domain}",
            "urls": "",
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "label": "bec",
        })
    return samples


def generate_impersonation_samples(
    n: int, target_domains: Optional[List[str]] = None
) -> List[Dict]:
    """Generate synthetic impersonation / brand-spoofing samples."""
    if target_domains is None:
        target_domains = [
            "microsoft.com", "google.com", "amazon.com", "github.com", "paypal.com",
        ]
    samples = []
    for _ in range(n):
        target = random.choice(target_domains)
        spoofed = _typosquat(target)
        display_name = random.choice(SPOOFED_DISPLAY_NAMES)
        service = random.choice(TARGET_SERVICES)
        phish_url = f"http://{spoofed}/verify?token={random.randint(10000, 99999)}"
        body = (
            f"Dear {_rand_first()},\n\n"
            f"We detected suspicious activity on your {service} account. "
            f"Please verify your identity immediately by clicking the link below:\n\n"
            f"{phish_url}\n\n"
            f"If you do not verify within 24 hours, your account will be suspended.\n\n"
            f"Regards,\n{display_name}"
        )
        samples.append({
            "subject": random.choice(IMPERSONATION_URGENT_SUBJECTS),
            "body": body,
            "sender": f"{display_name} <noreply@{spoofed}>",
            "reply_to": "",
            "urls": phish_url,
            "spf": random.choice(["fail", "softfail"]),
            "dkim": "fail",
            "dmarc": "fail",
            "label": "impersonation",
        })
    return samples


def generate_phishing_samples(n: int) -> List[Dict]:
    """Generate synthetic phishing email samples."""
    samples = []
    for _ in range(n):
        template = random.choice(PHISHING_TEMPLATES)
        phish_domain = _rand_domain()
        phish_url = f"http://{phish_domain}/claim?id={random.randint(1000, 9999)}"
        body = template.format(
            amount=f"{random.randint(100, 10_000):,}",
            url=phish_url,
            inv=random.randint(100000, 999999),
        )
        spf = random.choice(["fail", "softfail", "pass"])
        dkim = random.choice(["fail", "pass"])
        samples.append({
            "subject": random.choice([
                "Urgent: Account Action Required",
                "Your account has been compromised",
                "Claim your reward now",
                "Important: Verify your information",
                "Final notice - account suspension",
            ]),
            "body": body,
            "sender": f"{_rand_company()} <noreply@{phish_domain}>",
            "reply_to": f"support@{_rand_domain()}",
            "urls": phish_url,
            "spf": spf,
            "dkim": dkim,
            "dmarc": "fail" if spf == "fail" or dkim == "fail" else "pass",
            "label": "phishing",
        })
    return samples


def generate_spam_samples(n: int) -> List[Dict]:
    """Generate synthetic spam email samples."""
    samples = []
    for _ in range(n):
        template = random.choice(SPAM_TEMPLATES)
        spam_domain = _rand_domain()
        spam_url = f"http://{spam_domain}/shop?ref={random.randint(1000, 9999)}"
        body = template.format(
            product=random.choice(PRODUCTS),
            discount=random.randint(50, 90),
            url=spam_url,
            amount=random.randint(500, 5_000),
        )
        samples.append({
            "subject": f"SPECIAL OFFER - {random.randint(50, 90)}% OFF Today Only!",
            "body": body,
            "sender": f"{_rand_company()} <marketing@{spam_domain}>",
            "reply_to": "",
            "urls": spam_url,
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "label": "spam",
        })
    return samples


def generate_benign_samples(n: int) -> List[Dict]:
    """Generate synthetic legitimate/benign email samples."""
    samples = []
    legit_domains = ["company.com", "university.edu", "organization.org", "business.net"]
    for _ in range(n):
        template = random.choice(BENIGN_TEMPLATES)
        domain = random.choice(legit_domains)
        try:
            body = template.format(
                name=_rand_first(),
                time=_rand_time(),
                place=_rand_street(),
            )
        except KeyError:
            body = template
        sender_name = _rand_name()
        sender_local = sender_name.lower().replace(" ", ".")
        samples.append({
            "subject": f"Re: {random.choice(['Project Update', 'Meeting Notes', 'Follow-up', 'Quick Question', 'Document Review'])}",
            "body": body,
            "sender": f"{sender_name} <{sender_local}@{domain}>",
            "reply_to": "",
            "urls": "",
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "label": "benign",
        })
    return samples


# ---------------------------------------------------------------------------
# Dataset assembly
# ---------------------------------------------------------------------------

def generate_synthetic_dataset(
    n_bec: int = 100,
    n_impersonation: int = 100,
    n_phishing: int = 200,
    n_spam: int = 200,
    n_benign: int = 200,
    target_domains: Optional[List[str]] = None,
    random_state: int = 42,
    n_per_class: Optional[int] = None,
    seed: Optional[int] = None,
) -> pd.DataFrame:
    """
    Generate a balanced synthetic multi-class email dataset.

    IMPORTANT: This dataset is SYNTHETIC and suitable ONLY for integration testing.
    Do NOT use synthetic metrics as real-world performance claims.

    Returns:
        pd.DataFrame with columns: subject, body, sender, reply_to, urls, spf, dkim, dmarc, label
    """
    if seed is not None:
        random_state = seed
    if n_per_class is not None:
        n_bec = n_impersonation = n_phishing = n_spam = n_benign = n_per_class

    random.seed(random_state)
    np.random.seed(random_state)

    all_samples: List[Dict] = []
    all_samples.extend(generate_bec_samples(n_bec))
    all_samples.extend(generate_impersonation_samples(n_impersonation, target_domains))
    all_samples.extend(generate_phishing_samples(n_phishing))
    all_samples.extend(generate_spam_samples(n_spam))
    all_samples.extend(generate_benign_samples(n_benign))

    df = pd.DataFrame(all_samples)
    df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)

    # Dataset provenance metadata
    df.attrs["dataset_name"] = "synthetic_integration_test"
    df.attrs["dataset_source"] = "generated by ml/data/synthesize.py"
    df.attrs["dataset_license"] = "N/A (synthetic)"
    df.attrs["is_synthetic"] = True
    df.attrs["total_records"] = len(df)
    df.attrs["class_distribution"] = df["label"].value_counts().to_dict()

    return df


# Backwards-compatible alias
def generate_balanced_dataset(
    n_bec: int = 100,
    n_impersonation: int = 100,
    n_phishing: int = 200,
    n_spam: int = 200,
    n_benign: int = 200,
    target_domains: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Backwards-compatible wrapper for generate_synthetic_dataset."""
    return generate_synthetic_dataset(
        n_bec=n_bec,
        n_impersonation=n_impersonation,
        n_phishing=n_phishing,
        n_spam=n_spam,
        n_benign=n_benign,
        target_domains=target_domains,
    )