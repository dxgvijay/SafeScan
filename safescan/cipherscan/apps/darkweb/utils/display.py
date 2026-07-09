def safe_str(value, fallback="Unknown"):
    if value is None or (isinstance(value, str) and not value.strip()):
        return fallback
    return value


def safe_int(value, fallback=0):
    if value is None:
        return fallback
    try:
        return int(value)
    except (ValueError, TypeError):
        return fallback


def safe_date(date_str):
    return date_str if date_str else None


def format_data_classes(classes: list) -> str:
    if not classes:
        return "No public data available"
    if len(classes) <= 3:
        return ", ".join(classes)
    return ", ".join(classes[:3]) + f" and {len(classes) - 3} more"
