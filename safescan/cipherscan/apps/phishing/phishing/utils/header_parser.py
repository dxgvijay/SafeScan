import re
import ipaddress
import dns.resolver
import dns.exception
import requests
from email import policy
from email.parser import HeaderParser as EmailHeaderParser
from datetime import datetime, timezone
from django.conf import settings


def parse_email_headers(raw_headers):
    parser = EmailHeaderParser(policy=policy.default)
    msg = parser.parsestr(raw_headers)

    parsed = {}
    for key, val in msg.items():
        parsed[key] = str(val)

    parsed['_raw_headers'] = raw_headers

    from_addr = _extract_address(parsed.get('From', ''))
    reply_to = _extract_address(parsed.get('Reply-To', ''))
    return_path = _extract_address(parsed.get('Return-Path', ''))
    sender = _extract_address(parsed.get('Sender', ''))

    parsed['_from_email'] = from_addr
    parsed['_reply_to_email'] = reply_to
    parsed['_return_path_email'] = return_path
    parsed['_sender_email'] = sender

    parsed['_subject'] = parsed.get('Subject', '(No Subject)')
    parsed['_date'] = parsed.get('Date', '')
    parsed['_message_id'] = parsed.get('Message-ID', '')
    parsed['_mime_version'] = parsed.get('MIME-Version', '')
    parsed['_content_type'] = parsed.get('Content-Type', '')
    parsed['_authentication_results'] = parsed.get('Authentication-Results', '')
    parsed['_received_spf'] = parsed.get('Received-SPF', '')

    return parsed


def _extract_address(raw):
    if not raw:
        return ''
    match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', raw)
    return match.group(0) if match else raw.strip()


def extract_all_ips(parsed):
    ips = []
    received_headers = []

    for key in parsed:
        if key.lower().startswith('received'):
            received_headers.append(parsed[key])

    for header in received_headers:
        found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
        for ip_str in found:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not ip_obj.is_private:
                    ips.append(str(ip_obj))
            except ValueError:
                continue

    x_orig = parsed.get('X-Originating-IP', '')
    if x_orig:
        x_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', x_orig)
        for ip_str in x_ips:
            if ip_str not in ips:
                ips.append(ip_str)

    return list(dict.fromkeys(ips))


def trace_email_path(parsed):
    hops = []
    received_keys = sorted(
        [k for k in parsed if k.lower().startswith('received')],
        key=lambda k: len(parsed[k]),
        reverse=True,
    )

    for key in received_keys:
        value = parsed[key]
        hop = {'raw': value}

        ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', value)
        hop['ips'] = []
        for ip_str in ip_match:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                hop['ips'].append(str(ip_obj))
                hop['is_private'] = ip_obj.is_private
            except ValueError:
                continue

        from_match = re.search(r'from\s+(\S+)', value, re.IGNORECASE)
        hop['from'] = from_match.group(1) if from_match else ''

        by_match = re.search(r'by\s+(\S+)', value, re.IGNORECASE)
        hop['by'] = by_match.group(1) if by_match else ''

        with_match = re.search(r'with\s+(\S+)', value, re.IGNORECASE)
        hop['with'] = with_match.group(1) if with_match else ''

        date_match = re.search(r';\s*(.+)$', value)
        hop['date'] = date_match.group(1).strip() if date_match else ''

        id_match = re.search(r'id\s+(\S+)', value, re.IGNORECASE)
        hop['id'] = id_match.group(1) if id_match else ''

        hops.append(hop)

    return hops


def check_spf(domain):
    if not domain:
        return {'result': 'missing', 'detail': 'No domain to check'}

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if txt.startswith('v=spf1'):
                result = 'pass'
                detail = txt
                redirect = re.search(r'redirect\s*=\s*(\S+)', txt)
                if redirect:
                    detail += f' | redirect: {redirect.group(1)}'
                include = re.findall(r'include:(\S+)', txt)
                if include:
                    detail += f' | includes: {", ".join(include)}'
                if '~all' in txt:
                    result = 'softfail'
                elif '-all' in txt:
                    result = 'pass'
                elif '?all' in txt:
                    result = 'neutral'
                return {'result': result, 'detail': detail, 'domain': domain}

        return {'result': 'missing', 'detail': 'No SPF record found', 'domain': domain}

    except dns.resolver.NoAnswer:
        return {'result': 'missing', 'detail': 'No SPF record (no TXT records)', 'domain': domain}
    except dns.resolver.NXDOMAIN:
        return {'result': 'missing', 'detail': 'Domain does not exist', 'domain': domain}
    except dns.exception.DNSException as e:
        return {'result': 'error', 'detail': f'DNS lookup failed: {str(e)}', 'domain': domain}


def check_dkim(domain, selector='default'):
    if not domain:
        return {'result': 'missing', 'detail': 'No domain to check'}

    dkim_domain = f'{selector}._domainkey.{domain}'

    try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        records = []
        for rdata in answers:
            records.append(str(rdata))
        if records:
            return {
                'result': 'pass',
                'detail': 'DKIM record found',
                'domain': dkim_domain,
                'records': records,
            }
        return {'result': 'missing', 'detail': 'No DKIM record found', 'domain': dkim_domain}

    except dns.resolver.NoAnswer:
        return {'result': 'missing', 'detail': 'No DKIM record', 'domain': dkim_domain}
    except dns.resolver.NXDOMAIN:
        alt = f'selector1._domainkey.{domain}'
        try:
            answers = dns.resolver.resolve(alt, 'TXT')
            records = [str(r) for r in answers]
            return {
                'result': 'pass',
                'detail': 'DKIM record found (selector: selector1)',
                'domain': alt,
                'records': records,
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {'result': 'missing', 'detail': f'No DKIM record for selector "{selector}" or "selector1"', 'domain': domain}
        except dns.exception.DNSException as e:
            return {'result': 'error', 'detail': f'DKIM lookup failed: {str(e)}', 'domain': domain}
    except dns.exception.DNSException as e:
        return {'result': 'error', 'detail': f'DKIM lookup failed: {str(e)}', 'domain': domain}


def check_dmarc(domain):
    if not domain:
        return {'result': 'missing', 'detail': 'No domain to check'}

    dmarc_domain = f'_dmarc.{domain}'

    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if txt.startswith('v=DMARC1'):
                policy_match = re.search(r'p\s*=\s*(\w+)', txt)
                sp_match = re.search(r'sp\s*=\s*(\w+)', txt)
                pct_match = re.search(r'pct\s*=\s*(\d+)', txt)
                rua_match = re.search(r'rua\s*=\s*(\S+)', txt)
                ruf_match = re.search(r'ruf\s*=\s*(\S+)', txt)

                result = {
                    'result': 'pass',
                    'policy': policy_match.group(1) if policy_match else 'none',
                    'detail': txt,
                    'domain': dmarc_domain,
                }
                if sp_match:
                    result['subdomain_policy'] = sp_match.group(1)
                if pct_match:
                    result['percentage'] = int(pct_match.group(1))
                if rua_match:
                    result['report_uri'] = rua_match.group(1)
                if ruf_match:
                    result['forensic_uri'] = ruf_match.group(1)

                return result

        return {'result': 'missing', 'detail': 'No DMARC record found', 'domain': dmarc_domain}

    except dns.resolver.NoAnswer:
        return {'result': 'missing', 'detail': 'No DMARC record', 'domain': dmarc_domain}
    except dns.resolver.NXDOMAIN:
        return {'result': 'missing', 'detail': 'No DMARC record (NXDOMAIN)', 'domain': dmarc_domain}
    except dns.exception.DNSException as e:
        return {'result': 'error', 'detail': f'DMARC lookup failed: {str(e)}', 'domain': dmarc_domain}


def check_ip_reputation(ip):
    api_key = getattr(settings, 'ABUSEIPDB_API_KEY', '')
    if not api_key:
        return {
            'ip': ip,
            'score': 0,
            'category': 'unknown',
            'detail': 'No API key configured',
            'country': '',
            'isp': '',
            'usage_type': '',
            'domain': '',
            'is_whitelisted': False,
        }

    try:
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)
            return {
                'ip': ip,
                'score': score,
                'category': 'malicious' if score >= 50 else 'suspicious' if score >= 20 else 'safe',
                'detail': f'AbuseIPDB confidence score: {score}%',
                'country': data.get('countryCode', ''),
                'isp': data.get('isp', ''),
                'usage_type': data.get('usageType', ''),
                'domain': data.get('domain', ''),
                'is_whitelisted': data.get('isWhitelisted', False),
            }
        return {'ip': ip, 'score': 0, 'category': 'unknown', 'detail': f'API error: {resp.status_code}', 'country': '', 'isp': '', 'usage_type': '', 'domain': '', 'is_whitelisted': False}

    except requests.RequestException as e:
        return {'ip': ip, 'score': 0, 'category': 'unknown', 'detail': f'Request failed: {str(e)}', 'country': '', 'isp': '', 'usage_type': '', 'domain': '', 'is_whitelisted': False}


def detect_spoofing(parsed):
    issues = []

    from_email = parsed.get('_from_email', '')
    reply_to = parsed.get('_reply_to_email', '')
    return_path = parsed.get('_return_path_email', '')
    sender = parsed.get('_sender_email', '')

    from_domain = from_email.split('@')[-1] if '@' in from_email else ''
    reply_domain = reply_to.split('@')[-1] if '@' in reply_to else ''
    return_domain = return_path.split('@')[-1] if '@' in return_path else ''
    sender_domain = sender.split('@')[-1] if '@' in sender else ''

    if reply_to and from_domain and reply_domain:
        if from_domain != reply_domain:
            issues.append({
                'type': 'reply_to_mismatch',
                'severity': 'high',
                'message': f'Reply-To domain ({reply_domain}) does not match From domain ({from_domain}). '
                           f'Replies will go to a different domain than the claimed sender.',
            })

    if return_path and from_domain and return_domain:
        if from_domain != return_domain:
            issues.append({
                'type': 'return_path_mismatch',
                'severity': 'high',
                'message': f'Return-Path domain ({return_domain}) does not match From domain ({from_domain}). '
                           f'Bounces and DMARC reports go to a different domain.',
            })

    if sender and from_domain and sender_domain:
        if from_domain != sender_domain:
            issues.append({
                'type': 'sender_mismatch',
                'severity': 'medium',
                'message': f'Sender domain ({sender_domain}) does not match From domain ({from_domain}).',
            })

    display_name = parsed.get('From', '')
    name_match = re.match(r'^["\']?(.*?)["\']?\s*<', display_name)
    if name_match:
        name = name_match.group(1).strip()
        if name and from_email and name.lower() not in from_email.lower():
            if any(company in name.lower() for company in
                   ['support', 'security', 'admin', 'noreply', 'paypal', 'google',
                    'microsoft', 'amazon', 'apple', 'netflix', 'facebook',
                    'instagram', 'linkedin', 'twitter', 'bank', 'chase', 'wells']):
                issues.append({
                    'type': 'display_name_spoof',
                    'severity': 'critical',
                    'message': f'Display name "{name}" appears to impersonate a known brand/entity. '
                               f'This is a common phishing technique.',
                })

    auth_results = parsed.get('_authentication_results', '')
    if auth_results:
        spf_check = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        dkim_check = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        dmarc_check = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)

        if spf_check and spf_check.group(1).lower() in ('fail', 'softfail', 'permerror', 'temperror'):
            issues.append({
                'type': 'auth_spf_fail',
                'severity': 'high',
                'message': f'SPF authentication failed ({spf_check.group(1)}). '
                           f'The sending server is not authorized to send for this domain.',
            })
        if dkim_check and dkim_check.group(1).lower() in ('fail', 'permerror', 'temperror'):
            issues.append({
                'type': 'auth_dkim_fail',
                'severity': 'high',
                'message': f'DKIM authentication failed ({dkim_check.group(1)}). '
                           f'The email signature is invalid.',
            })
        if dmarc_check and dmarc_check.group(1).lower() in ('fail', 'permerror', 'temperror'):
            issues.append({
                'type': 'auth_dmarc_fail',
                'severity': 'critical',
                'message': f'DMARC authentication failed ({dmarc_check.group(1)}). '
                           f'The email failed domain-level authentication.',
            })

    return issues


def calculate_threat_score(spf, dkim, dmarc, spoofing_issues, ip_reputations):
    score = 0

    auth_weights = {
        'spf': {'pass': -5, 'softfail': 15, 'fail': 25, 'missing': 10, 'neutral': 5, 'error': 15},
        'dkim': {'pass': -5, 'fail': 25, 'missing': 10, 'error': 15},
        'dmarc': {
            'pass': -5,
            'fail': 30,
            'missing': 15,
            'error': 15,
        },
    }

    spf_result = spf.get('result', 'missing') if spf else 'missing'
    dkim_result = dkim.get('result', 'missing') if dkim else 'missing'
    dmarc_result = dmarc.get('result', 'missing') if dmarc else 'missing'

    dmarc_policy = dmarc.get('policy', '') if dmarc else ''
    if dmarc_result == 'pass' and dmarc_policy == 'reject':
        score -= 10
    elif dmarc_result == 'pass' and dmarc_policy == 'quarantine':
        score -= 5

    score += auth_weights['spf'].get(spf_result, 10)
    score += auth_weights['dkim'].get(dkim_result, 10)
    score += auth_weights['dmarc'].get(dmarc_result, 15)

    for issue in spoofing_issues:
        severity_map = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
        score += severity_map.get(issue.get('severity', 'low'), 5)

    for rep in ip_reputations:
        conf_score = rep.get('score', 0)
        if conf_score >= 80:
            score += 30
        elif conf_score >= 50:
            score += 20
        elif conf_score >= 20:
            score += 10

    score = max(0, min(100, score))
    return score


def get_threat_level(score):
    if score >= 70:
        return 'critical'
    elif score >= 45:
        return 'high'
    elif score >= 20:
        return 'suspicious'
    else:
        return 'safe'
