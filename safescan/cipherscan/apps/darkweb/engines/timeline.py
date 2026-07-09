from typing import Optional


def get_dates(breaches: list) -> tuple:
    dates = [
        b["date"] for b in breaches
        if isinstance(b.get("date"), str) and b["date"]
    ]
    if dates:
        dates.sort()
        return dates[0], dates[-1]
    return None, None
