def _evidence_recommendations(breaches: list) -> list:
    if not breaches:
        return [
            {"icon": "\u2705", "text": "No breach activity detected. Continue practicing good security hygiene.", "priority": "low"},
            {"icon": "\ud83d\udd04", "text": "Re-scan periodically. New breaches surface daily and your exposure status may change over time.", "priority": "low"},
        ]

    all_classes = set()
    for b in breaches:
        for dc in b.get("data_classes", []):
            all_classes.add(dc.lower())

    total_records = sum(b.get("records", 0) for b in breaches)
    recs = []

    recs.append({
        "icon": "\U0001f6e1\ufe0f",
        "text": f"Data found in {len(breaches)} breach(es) affecting {total_records:,}+ records. Review the exposed data types below.",
        "priority": "high" if len(breaches) >= 3 else "medium"
    })

    if any("password" in dc for dc in all_classes):
        recs.append({
            "icon": "\U0001f511",
            "text": "Change compromised passwords immediately. Use unique, complex passwords for each account and consider a password manager.",
            "priority": "critical"
        })

    if any("phone" in dc for dc in all_classes):
        recs.append({
            "icon": "\U0001f4f1",
            "text": "Enable SIM swap protection and port-out lock with your mobile carrier to prevent unauthorized transfers.",
            "priority": "high"
        })

    if any("email" in dc for dc in all_classes):
        recs.append({
            "icon": "\U0001f4e7",
            "text": "Enable multi-factor authentication (MFA) on all accounts associated with this email address.",
            "priority": "high"
        })

    if any(kw in dc for dc in all_classes for kw in ["credit", "payment", "financial", "bank"]):
        recs.append({
            "icon": "\U0001f4b3",
            "text": "Monitor bank and credit card statements for unauthorized transactions. Contact your financial institutions if you spot anything suspicious.",
            "priority": "critical"
        })

    if any(kw in dc for dc in all_classes for kw in ["social security", "government", "ssn", "driver"]):
        recs.append({
            "icon": "\U0001f464",
            "text": "Consider placing a fraud alert or credit freeze with the major credit bureaus to protect against identity theft.",
            "priority": "critical"
        })

    recs.append({
        "icon": "\U0001f504",
        "text": "Re-scan periodically. New breaches surface daily and your exposure status may change over time.",
        "priority": "low"
    })

    return recs


def generate_recommendations(breaches: list, exposures: list, risk: dict, query: str, asset_type: str) -> list:
    return _evidence_recommendations(breaches)
