import re
import json
import ssl
import socket
import idna
import requests
import dns.resolver
import dns.exception
import whois
from email import policy
from email.parser import Parser as EmailParser
from html.parser import HTMLParser
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from django.conf import settings


PHISHING_KEYWORDS = [
    'urgent', 'verify', 'account', 'suspended', 'click here', 'confirm',
    'password', 'security', 'update', 'restore', 'limited', 'blocked',
    'unauthorized', 'access', 'login', 'credential', 'bank', 'payment',
    'invoice', 'overdue', 'charge', 'refund', 'transaction', 'alert',
    'notification', 'unusual', 'activity', 'sign in', 'secure', 'protect',
    'validate', 'authenticate', 'lock', '冻结', '异常', '验证',
    'wire transfer', 'money order', 'western union', 'gift card',
    'lottery', 'prize', 'winner', 'inheritance', 'bitcoin', 'crypto',
    'investment', 'profit', 'bonus', 'discount', 'free', 'offer',
    'limited time', 'expires', 'deadline', 'action required',
    'immediate attention', 'respond now', 'failure to respond',
    'final notice', 'collection', 'legal', 'lawsuit', 'court',
    'IRS', 'tax', 'refund', 'stimulus', 'government', 'official',
    'social security', 'ssn', 'medicare', 'benefits', 'entitlement',
    'university', 'scholarship', 'grant', 'financial aid',
    'shipping', 'delivery', 'package', 'fedex', 'ups', 'dhl', 'usps',
    'order confirmation', 'tracking', 'receipt', 'purchase',
    'employment', 'job offer', 'work from home', 'remote job',
    'dating', 'romance', 'single', 'meet', 'match',
    'malware', 'virus', 'infection', 'scan', 'clean your computer',
    'technical support', 'microsoft', 'apple support', 'customer service',
    'phone number', 'call us', 'toll free', 'helpline',
    'donation', 'charity', 'fundraising', 'nonprofit',
    'emergency', 'help', 'please', 'dear customer', 'dear user',
    'click the link', 'copy and paste', 'open attachment',
    'download', 'install', 'update now', 'upgrade',
    'accept', 'agree', 'terms', 'conditions', 'privacy policy',
    'survey', 'questionnaire', 'feedback', 'reward',
    'congratulations', 'selected', 'chosen', 'eligible',
    'claim', 'redeem', 'collect', 'withdraw',
]

URGENCY_KEYWORDS = [
    'urgent', 'immediate', 'expires', 'deadline', 'final notice',
    'action required', 'respond now', 'limited time', 'immediately',
    'as soon as possible', 'today', 'within 24 hours', 'warning',
]

BRAND_IMPERSONATION = [
    'paypal', 'google', 'gmail', 'microsoft', 'outlook', 'hotmail',
    'amazon', 'apple', 'icloud', 'netflix', 'facebook', 'instagram',
    'linkedin', 'twitter', 'x.com', 'whatsapp', 'telegram',
    'chase', 'wells fargo', 'bank of america', 'citi', 'capital one',
    'american express', 'visa', 'mastercard', 'discover',
    'adp', 'docusign', 'dropbox', 'box', 'salesforce', 'slack',
    'zoom', 'teams', 'skype', 'webex',
    'irs', 'social security', 'medicare', 'gov', 'usps', 'fedex', 'ups',
]

DANGEROUS_EXTENSIONS = {
    '.exe': 'Executable',
    '.scr': 'Screen Saver',
    '.bat': 'Batch File',
    '.cmd': 'Command Script',
    '.com': 'Command File',
    '.vbs': 'VBScript',
    '.vbe': 'Encoded VBScript',
    '.js': 'JavaScript',
    '.jse': 'Encoded JavaScript',
    '.wsf': 'Windows Script',
    '.wsh': 'Windows Script Host',
    '.ps1': 'PowerShell Script',
    '.psm1': 'PowerShell Module',
    '.psd1': 'PowerShell Data',
    '.hta': 'HTML Application',
    '.html': 'HTML (with scripts)',
    '.htm': 'HTML (with scripts)',
    '.docm': 'Word Macro-Enabled',
    '.dotm': 'Word Macro-Enabled Template',
    '.xlsm': 'Excel Macro-Enabled',
    '.xltm': 'Excel Macro-Enabled Template',
    '.pptm': 'PowerPoint Macro-Enabled',
    '.ppsm': 'PowerPoint Macro-Enabled Show',
    '.jar': 'Java Archive',
    '.zip': 'Archive (encrypted)',
    '.rar': 'Archive (encrypted)',
    '.7z': 'Archive (encrypted)',
    '.cab': 'Cabinet File',
    '.msi': 'Windows Installer',
    '.msp': 'Windows Installer Patch',
    '.mst': 'Windows Installer Transform',
    '.lnk': 'Shortcut',
    '.iso': 'Disk Image',
    '.vhd': 'Virtual Hard Disk',
    '.appx': 'App Package',
    '.appxbundle': 'App Package Bundle',
    '.msix': 'MSIX Package',
    '.doc': 'Office Document (possible macro)',
    '.xls': 'Excel (possible macro)',
}

SUSPICIOUS_TLD = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.date', '.men', '.loan', '.click', '.download', '.review',
    '.stream', '.trade', '.webcam', '.science', '.party', '.racing',
]

HOMOGRAPH_CHARACTERS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'r', 'с': 'c', 'у': 'y',
    'х': 'x', 'і': 'i', 'ј': 'j', 'ο': 'o', 'а': 'a', 'е': 'e',
    'о': 'o', 'р': 'r', 'с': 'c', 'у': 'y', 'х': 'x',
}


def extract_links(email_body):
    url_regex = re.compile(
        r'(?:https?://|www\.)[^\s<>"\'{}|\\^`[\]]+'
        r'|(?:https?://|www\.)[^\s<>"\'{}|\\^`[\]]+',
        re.IGNORECASE
    )
    urls = url_regex.findall(email_body)
    cleaned = []
    for url in urls:
        url = url.rstrip('.,;:!?\'")]>')
        if url not in cleaned:
            cleaned.append(url)
    results = []
    for url in cleaned:
        try:
            parsed = urlparse(url if '://' in url else f'https://{url}')
            results.append({
                'url': url,
                'domain': parsed.netloc.lower(),
                'path': parsed.path or '/',
                'scheme': parsed.scheme or 'https',
                'has_ip': bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc.split(':')[0])),
                'subdomain_count': len(parsed.netloc.split('.')) - 2 if len(parsed.netloc.split('.')) > 2 else 0,
                'uses_https': parsed.scheme == 'https',
            })
        except Exception:
            results.append({'url': url, 'domain': '', 'path': '', 'scheme': '', 'has_ip': False, 'subdomain_count': 0, 'uses_https': False})
    return results


def check_link_reputation(url):
    vt_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    gsb_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')

    result = {
        'url': url,
        'malicious': False,
        'suspicious': False,
        'sources': [],
        'score': 0,
    }

    if gsb_key:
        try:
            resp = requests.post(
                f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}',
                json={
                    'client': {'clientId': 'cipherscan', 'clientVersion': '1.0.0'},
                    'threatInfo': {
                        'threatTypes': [
                            'MALWARE', 'SOCIAL_ENGINEERING',
                            'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION',
                            'THREAT_TYPE_UNSPECIFIED',
                        ],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}],
                    },
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if 'matches' in data:
                    result['malicious'] = True
                    result['score'] = max(result['score'], 80)
                    result['sources'].append({
                        'name': 'Google Safe Browsing',
                        'threats': [m['threatType'] for m in data['matches']],
                    })
        except requests.RequestException:
            pass

    if vt_key:
        try:
            resp = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                data={'url': url},
                headers={'x-apikey': vt_key},
                timeout=10,
            )
            if resp.status_code == 200:
                vt_data = resp.json()
                analysis_id = vt_data.get('data', {}).get('id', '')
                if analysis_id:
                    analysis_resp = requests.get(
                        f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                        headers={'x-apikey': vt_key},
                        timeout=10,
                    )
                    if analysis_resp.status_code == 200:
                        stats = analysis_resp.json().get('data', {}).get('attributes', {}).get('stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        if malicious > 0 or suspicious > 0:
                            vt_score = min(100, (malicious * 20) + (suspicious * 10))
                            result['score'] = max(result['score'], vt_score)
                            if malicious > 0:
                                result['malicious'] = True
                            if suspicious > 0:
                                result['suspicious'] = True
                            result['sources'].append({
                                'name': 'VirusTotal',
                                'malicious': malicious,
                                'suspicious': suspicious,
                                'harmless': stats.get('harmless', 0),
                                'undetected': stats.get('undetected', 0),
                            })
        except requests.RequestException:
            pass

    result['risk'] = 'malicious' if result['malicious'] else 'suspicious' if result['suspicious'] else 'unknown' if result['sources'] else 'unchecked'
    return result


def detect_phishing_keywords(subject, body):
    indicators = []
    text = f'{subject or ""} {body or ""}'.lower()
    text_clean = re.sub(r'<[^>]+>', '', text)

    matched_keywords = []
    for kw in PHISHING_KEYWORDS:
        if kw.lower() in text_clean:
            matched_keywords.append(kw)

    if matched_keywords:
        indicators.append({
            'type': 'phishing_keywords',
            'severity': 'medium',
            'count': len(matched_keywords),
            'details': 'Content contains phishing-related keywords',
            'matches': matched_keywords[:15],
        })

    urgency_count = 0
    for kw in URGENCY_KEYWORDS:
        count = text_clean.count(kw.lower())
        urgency_count += count
    if urgency_count >= 2:
        indicators.append({
            'type': 'urgency_language',
            'severity': 'medium',
            'count': urgency_count,
            'details': 'Email uses urgency/pressure tactics to rush action',
        })

    brand_matches = []
    for brand in BRAND_IMPERSONATION:
        if brand.lower() in text_clean:
            brand_matches.append(brand)
    if brand_matches:
        indicators.append({
            'type': 'brand_impersonation',
            'severity': 'high',
            'count': len(brand_matches),
            'details': 'Email references known brands to impersonate trust',
            'matches': brand_matches[:10],
        })

    money_patterns = [
        (r'\$\d{3,}', 'Large dollar amounts'),
        (r'\d{3,}\s*(?:dollars|USD|EUR|GBP)', 'Currency amounts'),
        (r'(?:bitcoin|btc|eth|usdt|crypto)\s*\d+', 'Cryptocurrency references'),
        (r'(?:wire|western union|money gram|gift card)', 'Money transfer methods'),
    ]
    for pattern, label in money_patterns:
        if re.search(pattern, text_clean, re.IGNORECASE):
            indicators.append({
                'type': 'financial_solicitation',
                'severity': 'high',
                'details': f'Email discusses financial transactions ({label})',
            })
            break

    if re.search(r'\b(?:password|passwd|pin|ssn|social security|credit card|cvv|security question)\b', text_clean, re.IGNORECASE):
        indicators.append({
            'type': 'credential_solicitation',
            'severity': 'critical',
            'details': 'Email explicitly asks for sensitive credentials or personal information',
        })

    return indicators


def detect_homograph_attacks(text):
    indicators = []
    urls = extract_links(text)
    checked = set()

    for link in urls:
        domain = link['domain']
        if domain in checked:
            continue
        checked.add(domain)

        for i, char in enumerate(domain):
            if char in HOMOGRAPH_CHARACTERS:
                expected = HOMOGRAPH_CHARACTERS[char]
                base = domain[:i] + expected + domain[i + 1:]
                if base != domain:
                    known_domains = [
                        'paypal.com', 'google.com', 'gmail.com', 'microsoft.com',
                        'amazon.com', 'apple.com', 'netflix.com', 'facebook.com',
                        'instagram.com', 'linkedin.com', 'twitter.com', 'whatsapp.com',
                        'chase.com', 'wellsfargo.com', 'bankofamerica.com',
                    ]
                    for known in known_domains:
                        if base == known or domain.endswith('.' + known):
                            indicators.append({
                                'type': 'homograph_attack',
                                'severity': 'critical',
                                'details': f'Homograph attack detected: {domain} impersonates {known} using lookalike characters',
                                'domain': domain,
                                'impersonates': known,
                            })
                            break

        punycode = domain.encode('idna').decode('ascii') if domain.startswith('xn--') else ''
        if punycode:
            decoded = idna.decode(domain) if domain.startswith('xn--') else ''
            if decoded and decoded != domain:
                indicators.append({
                    'type': 'internationalized_domain',
                    'severity': 'high',
                    'details': f'Internationalized domain name detected: {domain} decodes to "{decoded}"',
                    'domain': domain,
                    'decoded': decoded,
                })

    return indicators


def check_attachment_extensions(filename):
    name = filename.lower().strip('"\'')
    ext_match = re.search(r'(\.[a-z0-9]+)$', name)
    if not ext_match:
        return None

    ext = ext_match.group(1)
    if ext in DANGEROUS_EXTENSIONS:
        return {
            'filename': filename,
            'extension': ext,
            'risk': 'critical' if ext in ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.ps1', '.hta', '.jar', '.msi', '.lnk'] else 'high',
            'type': DANGEROUS_EXTENSIONS[ext],
        }

    if ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
        return {
            'filename': filename,
            'extension': ext,
            'risk': 'low',
            'type': 'Office Document',
        }

    return None


def check_sender_domain_age(domain):
    result = {
        'domain': domain,
        'age_days': None,
        'created_date': None,
        'registrar': '',
        'is_new': False,
        'status': 'unknown',
    }

    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if isinstance(created, str):
                created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%SZ')
                created = created.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - created
            result['age_days'] = age.days
            result['created_date'] = created.strftime('%Y-%m-%d')
            result['is_new'] = age.days < 30
            result['status'] = 'new_domain' if age.days < 30 else 'established' if age.days < 365 else 'aged'
        if w.registrar:
            result['registrar'] = str(w.registrar)
    except Exception:
        try:
            result['status'] = 'lookup_failed'
            answers = dns.resolver.resolve(domain, 'A')
            result['has_dns'] = bool(answers)
        except Exception:
            result['status'] = 'no_domain'

    return result


def analyze_email_structure(raw_email):
    issues = []
    structure = {
        'has_attachments': False,
        'attachment_count': 0,
        'content_types': [],
        'is_multipart': False,
        'has_html': False,
        'has_plain': False,
        'encoding': '',
    }

    try:
        msg = EmailParser(policy=policy.default).parsestr(raw_email)
        structure['is_multipart'] = msg.is_multipart()
        structure['content_types'] = [str(msg.get_content_type())]

        if msg.is_multipart():
            attachments = []
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                if content_type not in structure['content_types']:
                    structure['content_types'].append(content_type)

                if content_type == 'text/html':
                    structure['has_html'] = True
                elif content_type == 'text/plain':
                    structure['has_plain'] = True

                if 'attachment' in content_disposition:
                    structure['has_attachments'] = True
                    structure['attachment_count'] += 1
                    filename = part.get_filename() or 'unnamed'
                    ext_info = check_attachment_extensions(filename)
                    attachments.append({
                        'filename': filename,
                        'content_type': content_type,
                        'size': len(str(part)),
                        'risk': ext_info,
                    })
                    if ext_info:
                        issues.append({
                            'type': 'dangerous_attachment',
                            'severity': ext_info['risk'],
                            'details': f'Attachment "{filename}" ({ext_info["type"]}) is potentially dangerous',
                        })
        else:
            ct = msg.get_content_type()
            if ct == 'text/html':
                structure['has_html'] = True
            elif ct == 'text/plain':
                structure['has_plain'] = True

        encoding = msg.get('Content-Transfer-Encoding', '')
        structure['encoding'] = encoding

        has_mixed_encodings = False
        if structure['has_html'] and structure['has_plain']:
            has_mixed_encodings = True

        if structure['attachment_count'] > 0:
            issues.append({
                'type': 'has_attachments',
                'severity': 'low',
                'details': 'Email contains attachments',
            })

    except Exception:
        issues.append({
            'type': 'parse_error',
            'severity': 'low',
            'details': 'Could not fully parse email structure',
        })

    return structure, issues


def detect_html_tricks(html_body):
    indicators = []

    if not html_body:
        return indicators

    hidden_patterns = re.findall(
        r'style\s*=\s*["\'](?:[^"\']*)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|position\s*:\s*absolute[^;]*left\s*:\s*[-\d]|width\s*:\s*0|height\s*:\s*0)',
        html_body, re.IGNORECASE
    )
    if hidden_patterns:
        indicators.append({
            'type': 'hidden_content',
            'severity': 'high',
            'count': len(hidden_patterns),
            'details': 'HTML contains hidden elements (display:none, visibility:hidden, zero-size) often used to hide phishing text',
        })

    text_links = re.findall(r'>([^<]+)</a>', html_body)
    href_patterns = re.findall(r'href\s*=\s*["\'](https?://[^"\']+)["\']', html_body)

    mismatches = []
    for i, link_text in enumerate(text_links):
        if i < len(href_patterns):
            link_text_clean = link_text.strip().lower()
            href_domain = urlparse(href_patterns[i]).netloc.lower()
            if link_text_clean and href_domain and link_text_clean not in href_domain and href_domain not in link_text_clean:
                mismatches.append({
                    'text': link_text.strip()[:60],
                    'href': href_patterns[i][:100],
                })

    if mismatches:
        indicators.append({
            'type': 'link_text_mismatch',
            'severity': 'high',
            'count': len(mismatches),
            'details': 'Link display text does not match actual destination URL — classic phishing trick',
            'mismatches': mismatches[:10],
        })

    base_href = re.search(r'<base\s+href\s*=\s*["\']([^"\']+)["\']', html_body, re.IGNORECASE)
    if base_href:
        indicators.append({
            'type': 'base_tag_manipulation',
            'severity': 'critical',
            'details': f'HTML base tag hijacks relative links to: {base_href.group(1)}',
        })

    auto_redirects = re.findall(
        r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d*;\s*url\s*=\s*([^"\'>\s]+)',
        html_body, re.IGNORECASE
    )
    if auto_redirects:
        indicators.append({
            'type': 'auto_redirect',
            'severity': 'high',
            'count': len(auto_redirects),
            'details': 'HTML meta refresh redirect to external URL',
            'urls': auto_redirects[:5],
        })

    script_count = len(re.findall(r'<script', html_body, re.IGNORECASE))
    if script_count > 0:
        indicators.append({
            'type': 'inline_scripts',
            'severity': 'medium',
            'count': script_count,
            'details': 'Email contains JavaScript which may execute malicious actions',
        })

    tiny_font = re.findall(r'font-size\s*:\s*([0-9.]+)px', html_body, re.IGNORECASE)
    tiny_count = sum(1 for s in tiny_font if float(s) <= 3)
    if tiny_count > 0:
        indicators.append({
            'type': 'tiny_font',
            'severity': 'medium',
            'count': tiny_count,
            'details': 'HTML uses extremely small fonts (≤3px) to hide text from users',
        })

    iframe_count = len(re.findall(r'<iframe', html_body, re.IGNORECASE))
    if iframe_count > 0:
        indicators.append({
            'type': 'iframes',
            'severity': 'high',
            'count': iframe_count,
            'details': 'Email contains iframes which can load external content or track users',
        })

    return indicators


def calculate_risk_score(link_analysis, keyword_indicators, homograph_indicators,
                         attachment_indicators, domain_age_result, html_tricks,
                         structure_issues):
    score = 0
    breakdown = {}

    if link_analysis:
        total_links = len(link_analysis)
        malicious_links = sum(1 for l in link_analysis if l.get('reputation', {}).get('malicious'))
        suspicious_links = sum(1 for l in link_analysis if l.get('reputation', {}).get('suspicious'))
        unchecked_links = sum(1 for l in link_analysis if l.get('reputation', {}).get('risk') == 'unchecked')
        ip_links = sum(1 for l in link_analysis if l.get('has_ip'))

        link_score = 0
        if malicious_links > 0:
            link_score = min(30, 15 + malicious_links * 8)
        elif suspicious_links > 0:
            link_score = min(20, 10 + suspicious_links * 5)
        elif unchecked_links > 0 and total_links > 0:
            link_score = min(10, unchecked_links * 3)
        if ip_links > 0:
            link_score = min(35, link_score + ip_links * 10)

        score += link_score
        breakdown['links'] = {'score': link_score, 'max': 35, 'detail': f'{malicious_links} malicious, {suspicious_links} suspicious, {ip_links} IP-address links'}

    keyword_score = 0
    for ind in keyword_indicators:
        if ind['severity'] == 'critical':
            keyword_score += 20
        elif ind['severity'] == 'high':
            keyword_score += 12
        elif ind['severity'] == 'medium':
            keyword_score += 5
    keyword_score = min(keyword_score, 30)
    if keyword_score > 0:
        score += keyword_score
        breakdown['keywords'] = {'score': keyword_score, 'max': 30, 'detail': f'{len(keyword_indicators)} keyword-based indicators'}

    homograph_score = 0
    for ind in homograph_indicators:
        if ind['severity'] == 'critical':
            homograph_score += 25
        elif ind['severity'] == 'high':
            homograph_score += 15
    homograph_score = min(homograph_score, 30)
    if homograph_score > 0:
        score += homograph_score
        breakdown['homograph'] = {'score': homograph_score, 'max': 30, 'detail': f'{len(homograph_indicators)} homograph attack indicators'}

    attachment_score = 0
    for ind in attachment_indicators:
        if ind['severity'] == 'critical':
            attachment_score += 15
        elif ind['severity'] == 'high':
            attachment_score += 10
        elif ind['severity'] == 'medium':
            attachment_score += 5
    attachment_score = min(attachment_score, 20)
    if attachment_score > 0:
        score += attachment_score
        breakdown['attachments'] = {'score': attachment_score, 'max': 20, 'detail': f'{len(attachment_indicators)} attachment indicators'}

    domain_score = 0
    if domain_age_result:
        if domain_age_result.get('is_new'):
            domain_score += 15
        elif domain_age_result.get('status') == 'no_domain':
            domain_score += 25
        elif domain_age_result.get('status') == 'lookup_failed':
            domain_score += 5
        if domain_age_result.get('age_days') is not None and domain_age_result['age_days'] < 7:
            domain_score = max(domain_score, 20)
    if domain_score > 0:
        score += domain_score
        breakdown['domain'] = {'score': domain_score, 'max': 25, 'detail': f'Domain age: {domain_age_result.get("age_days", "unknown")} days'}

    html_score = 0
    for ind in html_tricks:
        if ind['severity'] == 'critical':
            html_score += 15
        elif ind['severity'] == 'high':
            html_score += 10
        elif ind['severity'] == 'medium':
            html_score += 5
    html_score = min(html_score, 20)
    if html_score > 0:
        score += html_score
        breakdown['html_tricks'] = {'score': html_score, 'max': 20, 'detail': f'{len(html_tricks)} HTML trick indicators'}

    structure_score = 0
    for issue in structure_issues:
        if issue['severity'] == 'critical':
            structure_score += 15
        elif issue['severity'] == 'high':
            structure_score += 10
        elif issue['severity'] == 'medium':
            structure_score += 5
        elif issue['severity'] == 'low':
            structure_score += 2
    structure_score = min(structure_score, 15)
    if structure_score > 0:
        score += structure_score
        breakdown['structure'] = {'score': structure_score, 'max': 15, 'detail': f'{len(structure_issues)} structural issues'}

    score = max(0, min(100, score))
    return score, breakdown


def get_verdict(score):
    if score > 70:
        return 'phishing'
    elif score >= 30:
        return 'suspicious'
    return 'clean'


def get_recommendations(indicators, verdict):
    recs = []

    if verdict == 'phishing':
        recs.append('Do not click any links or open attachments in this email.')
        recs.append('Do not reply to this email or provide any personal information.')
        recs.append('Report this email to your IT/security team immediately.')
        recs.append('If you entered credentials, change them immediately.')
        recs.append('Block the sender and mark as phishing in your email client.')

    if verdict == 'suspicious':
        recs.append('Exercise caution — this email exhibits suspicious characteristics.')
        recs.append('Verify the sender through an alternative communication channel.')
        recs.append('Hover over links before clicking to verify the actual destination.')
        recs.append('Do not provide sensitive information via email.')

    if verdict == 'clean':
        recs.append('No significant phishing indicators detected.')
        recs.append('Always remain vigilant when opening unexpected emails.')

    for ind in indicators:
        if ind.get('type') == 'homograph_attack':
            recs.append(f'Typo-squatting domain detected: {ind.get("domain", "")} — do not visit this site.')
        if ind.get('type') == 'credential_solicitation':
            recs.append('Legitimate organizations never ask for passwords via email.')
        if ind.get('type') == 'link_text_mismatch':
            recs.append('Verify link destinations before clicking — display text does not match the URL.')

    return recs


def analyze_suspicious_email(subject, sender_email, email_body, raw_email=None):
    if '@' in sender_email:
        sender_domain = sender_email.split('@')[-1].lower()
    else:
        sender_domain = sender_email.lower()

    links = extract_links(email_body)

    with ThreadPoolExecutor(max_workers=10) as executor:
        link_futures = {executor.submit(check_link_reputation, l['url']): l for l in links}

        for future in as_completed(link_futures):
            link = link_futures[future]
            try:
                link['reputation'] = future.result()
            except Exception:
                link['reputation'] = {'url': link['url'], 'malicious': False, 'suspicious': False, 'sources': [], 'score': 0, 'risk': 'unchecked'}

    keyword_indicators = detect_phishing_keywords(subject, email_body)
    homograph_indicators = detect_homograph_attacks(email_body)

    structure = {}
    structure_issues = []
    if raw_email:
        structure, structure_issues = analyze_email_structure(raw_email)

    html_tricks = []
    html_body = email_body if '<html' in email_body.lower() or '<!DOCTYPE' in email_body.upper() else ''
    if html_body:
        html_tricks = detect_html_tricks(html_body)

    domain_age = check_sender_domain_age(sender_domain)

    attachment_indicators = []
    for issue in structure_issues:
        if issue.get('type') == 'dangerous_attachment':
            attachment_indicators.append(issue)

    risk_score, breakdown = calculate_risk_score(
        links, keyword_indicators, homograph_indicators,
        attachment_indicators, domain_age, html_tricks, structure_issues,
    )

    verdict = get_verdict(risk_score)

    recommendations = get_recommendations(
        keyword_indicators + homograph_indicators + html_tricks + structure_issues,
        verdict,
    )

    all_indicators = keyword_indicators + homograph_indicators + html_tricks + structure_issues

    return {
        'sender_domain': sender_domain,
        'links': links,
        'keyword_indicators': keyword_indicators,
        'homograph_indicators': homograph_indicators,
        'html_tricks': html_tricks,
        'domain_age': domain_age,
        'email_structure': structure,
        'risk_score': risk_score,
        'risk_breakdown': breakdown,
        'verdict': verdict,
        'recommendations': recommendations,
        'indicators': all_indicators,
    }
