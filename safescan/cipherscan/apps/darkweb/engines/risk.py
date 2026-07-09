from typing import Dict, List


def _risk_level(score: int) -> str:
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


def calculate_risk_score(breaches: list) -> dict:
    if not breaches:
        return {"score": 0, "level": "low", "factors": []}

    score = 0
    factors = []

    verified_count = sum(1 for b in breaches if b.get("is_verified", False))
    unverified_count = sum(1 for b in breaches if not b.get("is_verified", False))

    if verified_count > 0:
        points = verified_count * 20
        score += points
        factors.append({"label": f"Appears in {verified_count} verified breach(es)", "points": points})

    if unverified_count > 0:
        points = unverified_count * 10
        score += points
        factors.append({"label": f"Appears in {unverified_count} unverified breach(es)", "points": points})

    all_classes = set()
    for b in breaches:
        for dc in b.get("data_classes", []):
            all_classes.add(dc.lower())

    if any("password" in dc for dc in all_classes):
        score += 25
        factors.append({"label": "Password exposed", "points": 25})

    if any("phone" in dc for dc in all_classes):
        score += 15
        factors.append({"label": "Phone exposed", "points": 15})

    if any(kw in dc for dc in all_classes for kw in ["social security", "government id", "ssn", "government"]):
        score += 30
        factors.append({"label": "Government ID exposed", "points": 30})

    if any(kw in dc for dc in all_classes for kw in ["credit card", "credit", "payment card", "financial"]):
        score += 35
        factors.append({"label": "Credit Card exposed", "points": 35})

    if any("medical" in dc for dc in all_classes):
        score += 30
        factors.append({"label": "Medical Data exposed", "points": 30})

    if any("security question" in dc for dc in all_classes):
        score += 15
        factors.append({"label": "Security Questions exposed", "points": 15})

    has_email = any("email" in dc for dc in all_classes)
    if has_email and len(all_classes) == 1 and all("email" in dc for dc in all_classes):
        score += 5
        factors.append({"label": "Email address exposed", "points": 5})

    score = min(score, 100)
    level = _risk_level(score)

    return {"score": score, "level": level, "factors": factors}
