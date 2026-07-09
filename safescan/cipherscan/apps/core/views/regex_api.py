import re
import json

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt


FLAG_MAP = {
    "g": 0,
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "u": re.UNICODE,
    "y": 0,
}

CHARACTER_CLASSES = {
    r"\d": "Digit [0-9]",
    r"\D": "Non-digit",
    r"\w": "Word char [a-zA-Z0-9_]",
    r"\W": "Non-word char",
    r"\s": "Whitespace",
    r"\S": "Non-whitespace",
    r".": "Any char (except newline)",
    r"\b": "Word boundary",
    r"\B": "Non-word boundary",
    r"^": "Start of string",
    r"$": "End of string",
    r"\A": "Start of string (absolute)",
    r"\Z": "End of string (absolute)",
    r"\t": "Tab",
    r"\n": "Newline",
    r"\r": "Carriage return",
}

ANCHORED_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "url": r"https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "ipv6": r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b",
    "phone": r"\+?\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "password": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
    "username": r"^[a-zA-Z0-9_]{3,20}$",
    "hex_color": r"#?([a-fA-F0-9]{3}|[a-fA-F0-9]{6})\b",
    "mac_address": r"\b(?:[a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2}\b",
    "uuid": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
}

ANCHORED_LABELS = {
    "email": "Email Address",
    "url": "URL",
    "ipv4": "IPv4 Address",
    "ipv6": "IPv6 Address",
    "phone": "Phone Number",
    "credit_card": "Credit Card Number",
    "password": "Strong Password",
    "username": "Username",
    "hex_color": "Hex Color",
    "mac_address": "MAC Address",
    "uuid": "UUID",
}

COMMON_PATTERNS = [
    {"id": "email", "label": "Email Address", "pattern": ANCHORED_PATTERNS["email"]},
    {"id": "url", "label": "URL", "pattern": ANCHORED_PATTERNS["url"]},
    {"id": "ipv4", "label": "IPv4 Address", "pattern": ANCHORED_PATTERNS["ipv4"]},
    {"id": "ipv6", "label": "IPv6 Address", "pattern": ANCHORED_PATTERNS["ipv6"]},
    {"id": "phone", "label": "Phone Number", "pattern": ANCHORED_PATTERNS["phone"]},
    {"id": "credit_card", "label": "Credit Card", "pattern": ANCHORED_PATTERNS["credit_card"]},
    {"id": "password", "label": "Strong Password", "pattern": ANCHORED_PATTERNS["password"]},
    {"id": "username", "label": "Username", "pattern": ANCHORED_PATTERNS["username"]},
    {"id": "hex_color", "label": "Hex Color", "pattern": ANCHORED_PATTERNS["hex_color"]},
    {"id": "mac_address", "label": "MAC Address", "pattern": ANCHORED_PATTERNS["mac_address"]},
    {"id": "uuid", "label": "UUID", "pattern": ANCHORED_PATTERNS["uuid"]},
]

CHEAT_SHEET = [
    {"section": "Anchors", "items": [
        {"pattern": "^", "desc": "Start of string"},
        {"pattern": "$", "desc": "End of string"},
        {"pattern": "\\b", "desc": "Word boundary"},
        {"pattern": "\\B", "desc": "Non-word boundary"},
    ]},
    {"section": "Character Classes", "items": [
        {"pattern": "\\d", "desc": "Digit [0-9]"},
        {"pattern": "\\D", "desc": "Non-digit"},
        {"pattern": "\\w", "desc": "Word [a-zA-Z0-9_]"},
        {"pattern": "\\W", "desc": "Non-word"},
        {"pattern": "\\s", "desc": "Whitespace"},
        {"pattern": "\\S", "desc": "Non-whitespace"},
        {"pattern": ".", "desc": "Any char (except newline)"},
    ]},
    {"section": "Quantifiers", "items": [
        {"pattern": "*", "desc": "0 or more"},
        {"pattern": "+", "desc": "1 or more"},
        {"pattern": "?", "desc": "0 or 1"},
        {"pattern": "{n}", "desc": "Exactly n"},
        {"pattern": "{n,}", "desc": "n or more"},
        {"pattern": "{n,m}", "desc": "n to m"},
    ]},
    {"section": "Groups", "items": [
        {"pattern": "(...)", "desc": "Capture group"},
        {"pattern": "(?:...)", "desc": "Non-capture group"},
        {"pattern": "(?=...)", "desc": "Lookahead"},
        {"pattern": "(?!...)", "desc": "Negative lookahead"},
        {"pattern": "(?<=...)", "desc": "Lookbehind"},
        {"pattern": "(?<!...)", "desc": "Negative lookbehind"},
    ]},
    {"section": "Flags", "items": [
        {"pattern": "g", "desc": "Global (all matches)"},
        {"pattern": "i", "desc": "Case insensitive"},
        {"pattern": "m", "desc": "Multiline"},
        {"pattern": "s", "desc": "Dotall (dot matches newline)"},
        {"pattern": "u", "desc": "Unicode"},
    ]},
    {"section": "Escaped Characters", "items": [
        {"pattern": "\\t", "desc": "Tab"},
        {"pattern": "\\n", "desc": "Newline"},
        {"pattern": "\\r", "desc": "Carriage return"},
        {"pattern": "\\\\", "desc": "Backslash"},
        {"pattern": "\\/", "desc": "Forward slash"},
    ]},
]


def _compile_pattern(pattern, flags):
    re_flags = 0
    for f in flags:
        re_flags |= FLAG_MAP.get(f, 0)
    return re.compile(pattern, re_flags)


def _build_match_data(match, pattern_obj):
    groups_dict = {}
    if pattern_obj.groups:
        for i in range(1, pattern_obj.groups + 1):
            name = pattern_obj.groupindex.get(i)
            val = match.group(i)
            groups_dict[str(i)] = {
                "name": name,
                "value": val,
                "start": match.start(i),
                "end": match.end(i),
            }

    named_groups = {}
    for name, idx in pattern_obj.groupindex.items():
        named_groups[name] = {
            "value": match.group(name),
            "start": match.start(name),
            "end": match.end(name),
        }

    return {
        "full": match.group(0),
        "start": match.start(0),
        "end": match.end(0),
        "groups": groups_dict,
        "named_groups": named_groups,
    }


@csrf_exempt
@require_http_methods(["POST"])
def regex_test_view(request):
    try:
        body = json.loads(request.body)
        pattern_str = body.get("pattern", "")
        test_text = body.get("text", "")
        flags = body.get("flags", [])

        if not pattern_str:
            return JsonResponse({"error": "Regex pattern is required"}, status=400)

        if not isinstance(flags, list):
            flags = []

        try:
            compiled = _compile_pattern(pattern_str, flags)
        except re.error as e:
            msg = str(e)
            pos = getattr(e, "pos", -1)
            lineno = getattr(e, "lineno", -1)
            col = getattr(e, "col", -1)
            return JsonResponse({
                "error": f"Regex error: {msg}",
                "error_detail": {
                    "message": msg,
                    "position": pos,
                    "line": lineno,
                    "col": col,
                }
            }, status=400)

        if not test_text:
            return JsonResponse({
                "matches": [],
                "match_count": 0,
                "groups_count": compiled.groups,
                "named_groups_count": len(compiled.groupindex),
                "named_groups_list": list(compiled.groupindex.keys()),
                "pattern": pattern_str,
                "flags": flags,
                "error": None,
            })

        is_global = "g" in flags

        if is_global:
            matches_data = []
            for match in compiled.finditer(test_text):
                matches_data.append(_build_match_data(match, compiled))
            match_count = len(matches_data)
        else:
            match = compiled.search(test_text)
            matches_data = []
            if match:
                matches_data.append(_build_match_data(match, compiled))
            match_count = 1 if match else 0

        return JsonResponse({
            "matches": matches_data,
            "match_count": match_count,
            "groups_count": compiled.groups,
            "named_groups_count": len(compiled.groupindex),
            "named_groups_list": list(compiled.groupindex.keys()),
            "pattern": pattern_str,
            "flags": flags,
            "error": None,
        })

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def regex_templates_view(request):
    templates = []
    for pt in COMMON_PATTERNS:
        templates.append({
            "id": pt["id"],
            "label": pt["label"],
            "pattern": pt["pattern"],
        })
    return JsonResponse({
        "templates": templates,
        "cheat_sheet": CHEAT_SHEET,
    })


@csrf_exempt
@require_http_methods(["GET"])
def regex_cheatsheet_view(request):
    return JsonResponse({"cheat_sheet": CHEAT_SHEET})
