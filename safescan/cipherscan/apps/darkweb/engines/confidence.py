def calculate_confidence(breaches: list) -> int:
    if not breaches:
        return 15

    has_hibp = any(b.get("source") == "Have I Been Pwned" for b in breaches)
    all_verified = all(b.get("is_verified", False) for b in breaches)
    any_verified = any(b.get("is_verified", False) for b in breaches)
    breach_count = len(breaches)

    all_classes = set()
    for b in breaches:
        all_classes.update(b.get("data_classes", []))
    class_count = len(all_classes)

    years = set()
    for b in breaches:
        try:
            years.add(int(b["date"][:4]))
        except (ValueError, KeyError):
            pass

    if has_hibp and all_verified and breach_count >= 3:
        return 98

    if has_hibp and all_verified:
        return 95

    if has_hibp and any_verified:
        return 90

    if has_hibp:
        bonus = 0
        if class_count >= 6:
            bonus += 3
        elif class_count >= 3:
            bonus += 1
        if len(years) >= 3:
            bonus += 2
        return min(80 + bonus, 89)

    if breach_count >= 3 and class_count >= 3:
        return 75

    if breach_count >= 1 and class_count >= 3:
        return 65

    if breach_count >= 1:
        return 40

    return 15
