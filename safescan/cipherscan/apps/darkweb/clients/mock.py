import hashlib
import logging
import random
from typing import Optional

from apps.darkweb.clients.base import DarkWebProvider, BreachSearchResult

logger = logging.getLogger(__name__)

BREACH_TEMPLATES = [
    {
        "name": "Collection1",
        "title": "Collection #1",
        "domain": "collection.com",
        "date": "2019-01-07",
        "data_classes": ["Email addresses", "Passwords", "Usernames", "IP addresses"],
        "description": "A massive credential stuffing list compiled from multiple sources.",
        "is_verified": True,
    },
    {
        "name": "LinkedIn",
        "title": "LinkedIn",
        "domain": "linkedin.com",
        "date": "2012-05-05",
        "data_classes": ["Email addresses", "Passwords"],
        "description": "Data scraped from LinkedIn's database containing email and password pairs.",
        "is_verified": True,
    },
    {
        "name": "Adobe",
        "title": "Adobe",
        "domain": "adobe.com",
        "date": "2013-10-04",
        "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "description": "Customer data from Adobe's compromised database.",
        "is_verified": True,
    },
    {
        "name": "Dropbox",
        "title": "Dropbox",
        "domain": "dropbox.com",
        "date": "2012-07-01",
        "data_classes": ["Email addresses", "Passwords"],
        "description": "Employee email addresses and password hashes from Dropbox.",
        "is_verified": True,
    },
    {
        "name": "MyFitnessPal",
        "title": "MyFitnessPal",
        "domain": "myfitnesspal.com",
        "date": "2018-02-01",
        "data_classes": ["Email addresses", "Passwords", "Usernames"],
        "description": "User account data from the MyFitnessPal fitness platform breach.",
        "is_verified": True,
    },
    {
        "name": "Facebook",
        "title": "Facebook",
        "domain": "facebook.com",
        "date": "2019-04-14",
        "data_classes": ["Email addresses", "Names", "Phone numbers", "Dates of birth"],
        "description": "Scraped profile data from Facebook's platform.",
        "is_verified": True,
    },
    {
        "name": "Canva",
        "title": "Canva",
        "domain": "canva.com",
        "date": "2019-05-24",
        "data_classes": ["Email addresses", "Names", "Usernames", "Passwords"],
        "description": "User data from the Canva graphic design platform breach.",
        "is_verified": True,
    },
    {
        "name": "Dubsmash",
        "title": "Dubsmash",
        "domain": "dubsmash.com",
        "date": "2018-12-01",
        "data_classes": ["Email addresses", "Names", "Usernames", "Passwords", "Phone numbers"],
        "description": "User database from the Dubsmash video app breach.",
        "is_verified": True,
    },
    {
        "name": "DataEnrichment",
        "title": "Data Enrichment Service",
        "domain": "dataenrichment.com",
        "date": "2020-05-01",
        "data_classes": ["Email addresses", "Names", "Phone numbers", "Physical addresses", "Dates of birth"],
        "description": "Aggregated consumer data from a marketing data enrichment service.",
        "is_verified": False,
    },
    {
        "name": "CredentialLeak2021",
        "title": "General Credential Leak 2021",
        "domain": "",
        "date": "2021-06-15",
        "data_classes": ["Email addresses", "Passwords", "Usernames"],
        "description": "Credential stuffing list discovered on underground forums.",
        "is_verified": False,
    },
    {
        "name": "FinancialDataBreach",
        "title": "Financial Services Breach",
        "domain": "financeservices.com",
        "date": "2022-03-01",
        "data_classes": ["Email addresses", "Names", "Credit cards", "Financial data", "Phone numbers"],
        "description": "Customer financial records from a compromised fintech platform.",
        "is_verified": False,
    },
    {
        "name": "SocialMediaLeak",
        "title": "Social Media Data Leak",
        "domain": "socialmedia.io",
        "date": "2023-01-10",
        "data_classes": ["Email addresses", "Names", "Usernames", "Social Media profiles"],
        "description": "Aggregated data from multiple social media scraping operations.",
        "is_verified": False,
    },
    {
        "name": "GovernmentDataDump",
        "title": "Government Records Exposure",
        "domain": "govrecords.gov",
        "date": "2022-11-20",
        "data_classes": ["Email addresses", "Names", "Government IDs", "SSN", "Dates of birth", "Physical addresses"],
        "description": "Citizen records exposed from a government database misconfiguration.",
        "is_verified": True,
    },
    {
        "name": "HealthDataLeak",
        "title": "Healthcare Data Exposure",
        "domain": "healthcarepro.com",
        "date": "2023-04-05",
        "data_classes": ["Email addresses", "Names", "Medical records", "Phone numbers", "Physical addresses"],
        "description": "Patient records exposed through a healthcare provider data breach.",
        "is_verified": True,
    },
    {
        "name": "GamingForumBleed",
        "title": "Gaming Community Forum Leak",
        "domain": "gamingforum.net",
        "date": "2020-08-12",
        "data_classes": ["Email addresses", "Passwords", "Usernames", "IP addresses"],
        "description": "User database from a popular gaming forum breached via SQL injection.",
        "is_verified": True,
    },
]

SEVERITY_MAP = {
    "Email addresses": "medium",
    "Passwords": "high",
    "Usernames": "low",
    "IP addresses": "medium",
    "Names": "medium",
    "Phone numbers": "high",
    "Dates of birth": "medium",
    "Physical addresses": "high",
    "Credit cards": "critical",
    "Financial data": "high",
    "Government IDs": "critical",
    "SSN": "critical",
    "Medical records": "critical",
    "Social Media profiles": "low",
    "Password hints": "high",
}


def _query_seed(query: str) -> int:
    return int(hashlib.sha256(query.lower().strip().encode()).hexdigest(), 16)


def _derive_severity(data_classes: list) -> str:
    score = 0
    for dc in data_classes:
        sev = SEVERITY_MAP.get(dc, "medium")
        if sev == "critical":
            score = max(score, 3)
        elif sev == "high":
            score = max(score, 2)
        elif sev == "medium":
            score = max(score, 1)
    mapping = {0: "low", 1: "medium", 2: "high", 3: "critical", 4: "critical", 5: "critical"}
    return mapping.get(score, "low")


def _generate_breaches(query: str, seed: int, count: int) -> list:
    rng = random.Random(seed)
    template_count = len(BREACH_TEMPLATES)

    picks = []
    used_indices = set()
    for _ in range(count):
        idx = rng.randint(0, template_count - 1)
        attempts = 0
        while idx in used_indices and attempts < 20:
            idx = rng.randint(0, template_count - 1)
            attempts += 1
        used_indices.add(idx)
        picks.append(BREACH_TEMPLATES[idx])

    breaches = []
    for tpl in picks:
        record_count = rng.randint(1000, 500_000_000)
        severity = _derive_severity(tpl["data_classes"])

        breaches.append({
            "name": tpl["name"],
            "title": tpl["title"],
            "domain": tpl["domain"],
            "date": tpl["date"],
            "records": record_count,
            "data_classes": tpl["data_classes"],
            "description": tpl["description"],
            "source": "Have I Been Pwned",
            "risk": severity,
            "incident_type": "Data Breach",
            "is_verified": tpl["is_verified"],
            "is_spam_list": False,
            "logo_path": "",
            "references": [f"https://haveibeenpwned.com/PwnedWebsites#{tpl['name']}"],
        })

    return breaches


class MockProvider(DarkWebProvider):

    def __init__(self):
        logger.info("[MockProvider] Initialized — generating simulated breach data")

    def search_breaches(
        self, indicator: str, indicator_type: Optional[str] = None
    ) -> BreachSearchResult:
        normalised = indicator.strip().lower()

        if not indicator_type:
            indicator_type = self.detect_asset_type(indicator)

        seed = _query_seed(normalised)

        if indicator_type == "email":
            rng = random.Random(seed)
            breach_count = rng.choices(
                [0, 1, 2, 3, 4],
                weights=[5, 25, 35, 25, 10],
                k=1
            )[0]
        else:
            rng = random.Random(seed)
            breach_count = rng.choices(
                [0, 1, 2],
                weights=[40, 40, 20],
                k=1
            )[0]

        breaches = _generate_breaches(normalised, seed, breach_count)

        logger.info("[MockProvider] Returning %d simulated breaches for %s (type=%s)",
                     len(breaches), normalised, indicator_type)

        return BreachSearchResult(
            success=True,
            indicator=normalised,
            indicator_type=indicator_type,
            breaches=breaches,
        )
