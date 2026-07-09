import re
import email
from email import policy

import dns.resolver

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from apps.accounts.utils.scan_history_helper import save_scan_history
from apps.phishing.phishing.models import (
    DomainHealthScan,
    EmailContentScan,
    EmailHeaderScan,
    EmailHealthCheck,
    SuspiciousEmailReport,
)


class PhishingStatsView(APIView):
    def get(self, request):
        return Response({
            'headers_analyzed': EmailHeaderScan.objects.count(),
            'emails_blocked': SuspiciousEmailReport.objects.filter(
                verdict__in=['suspicious', 'phishing']
            ).count(),
            'domains_checked': EmailHealthCheck.objects.count(),
        })


@api_view(['POST'])
def email_header_analyze_view(request):
    header_text = request.data.get('header', '')
    if not header_text:
        return Response({'error': 'Header is required'}, status=status.HTTP_400_BAD_REQUEST)

    msg = email.message_from_string(header_text, policy=policy.default)

    from_email = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    return_path = msg.get('Return-Path', '')
    subject = msg.get('Subject', '')
    date = msg.get('Date', '')
    message_id = msg.get('Message-ID', '')

    received_headers = msg.get_all('Received', [])
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    hops = []
    for rh in received_headers:
        hops.extend(re.findall(ip_pattern, rh))

    auth_results = msg.get('Authentication-Results', '')
    auth_lower = auth_results.lower()
    spf_result = 'pass' if 'spf=pass' in auth_lower else 'fail' if 'spf=fail' in auth_lower else 'none'
    dkim_result = 'pass' if 'dkim=pass' in auth_lower else 'fail' if 'dkim=fail' in auth_lower else 'none'
    dmarc_result = 'pass' if 'dmarc=pass' in auth_lower else 'fail' if 'dmarc=fail' in auth_lower else 'none'

    score = 0
    if spf_result == 'fail': score += 25
    if dkim_result == 'fail': score += 25
    if dmarc_result == 'fail': score += 20
    if reply_to and reply_to != from_email: score += 15
    if return_path and return_path not in from_email: score += 15
    from_domain = ''
    return_domain = ''
    if from_email:
        m = re.search(r'@([\w.-]+)', from_email)
        if m: from_domain = m.group(1)
    if return_path:
        m = re.search(r'@([\w.-]+)', return_path)
        if m: return_domain = m.group(1)
    if from_domain and return_domain and from_domain != return_domain:
        score += 20
    score = min(score, 100)

    if score >= 70:
        verdict = 'High Risk — Likely Phishing'
    elif score >= 40:
        verdict = 'Medium Risk — Suspicious'
    elif score >= 15:
        verdict = 'Low Risk — Minor Issues'
    else:
        verdict = 'Clean — Looks Legitimate'
    is_malicious = score >= 40

    reasons = []
    if spf_result == 'fail':
        reasons.append('SPF check failed — sender not authorized')
    if dkim_result == 'fail':
        reasons.append('DKIM signature invalid — email may be forged')
    if dmarc_result == 'fail':
        reasons.append('DMARC policy failed — domain impersonation risk')
    if reply_to != from_email:
        reasons.append('Reply-To differs from From — redirect attempt')
    if return_path not in from_email:
        reasons.append('Return-Path mismatch — bounce address manipulation')

    scan = EmailHeaderScan.objects.create(
        raw_header=header_text,
        from_email=from_email,
        sender_ip=hops[0] if hops else None,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        spoofing_detected=is_malicious,
        threat_score=score,
        is_malicious=is_malicious,
        hops=hops,
        analysis_result={
            'reasons': reasons,
            'verdict': verdict,
            'subject': subject,
            'reply_to': reply_to,
            'return_path': return_path,
            'message_id': message_id,
            'date': date,
        },
    )

    save_scan_history(
        user=request.user,
        scan_type='EMAIL',
        target=from_email or 'unknown',
        verdict='MALICIOUS' if is_malicious else 'SUSPICIOUS' if score >= 15 else 'SAFE',
        threat_score=score,
        engine='phishing-analyzer',
        metadata={
            'scan_id': scan.id,
            'spf_result': spf_result,
            'dkim_result': dkim_result,
            'dmarc_result': dmarc_result,
            'subject': subject,
        },
    )

    return Response({
        'scan_id': scan.id,
        'from_email': from_email,
        'subject': subject,
        'date': date,
        'spf_result': spf_result,
        'dkim_result': dkim_result,
        'dmarc_result': dmarc_result,
        'threat_score': score,
        'verdict': verdict,
        'is_malicious': is_malicious,
        'reasons': reasons,
        'hops': hops,
        'reply_to': reply_to,
        'return_path': return_path,
        'message_id': message_id,
    })


@api_view(['POST'])
def domain_health_view(request):
    domain = request.data.get('domain', '').strip().lower()
    if not domain:
        return Response({'error': 'Domain is required'}, status=status.HTTP_400_BAD_REQUEST)

    mx_list = []
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_list = [str(r.exchange) for r in mx_records]
    except Exception:
        pass

    spf = None
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf = next((str(r) for r in txt_records if 'v=spf1' in str(r)), None)
    except Exception:
        pass

    dmarc_record = None
    try:
        dmarc = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        dmarc_record = str(list(dmarc)[0])
    except Exception:
        pass

    score = 100
    issues = []
    if not mx_list:
        score -= 30
        issues.append('No MX records found — domain cannot receive email')
    if not spf:
        score -= 25
        issues.append('No SPF record — anyone can spoof this domain')
    if not dmarc_record:
        score -= 25
        issues.append('No DMARC policy — no protection against spoofing')
    if spf and 'all' not in spf:
        score -= 10
        issues.append('SPF record incomplete — missing catch-all policy')
    score = max(0, score)

    if score >= 90:
        grade = 'A'
    elif score >= 75:
        grade = 'B'
    elif score >= 60:
        grade = 'C'
    elif score >= 40:
        grade = 'D'
    else:
        grade = 'F'

    DomainHealthScan.objects.create(
        domain=domain,
        mx_records=mx_list,
        spf_record=spf,
        dmarc_record=dmarc_record,
        dkim_found=bool(dmarc_record and 'dkim' in dmarc_record.lower()),
        health_score=score,
        health_grade=grade,
        issues=issues,
    )

    return Response({
        'domain': domain,
        'mx_records': mx_list,
        'spf_record': spf,
        'dmarc_record': dmarc_record,
        'health_score': score,
        'health_grade': grade,
        'issues': issues,
        'has_mx': bool(mx_list),
        'has_spf': bool(spf),
        'has_dmarc': bool(dmarc_record),
    })


@api_view(['POST'])
def email_content_scan_view(request):
    email_body = request.data.get('email_body', '')
    if not email_body:
        return Response({'error': 'Email body is required'}, status=status.HTTP_400_BAD_REQUEST)

    score = 0
    indicators = []

    urgency_words = ['urgent', 'immediately', 'act now', 'expires',
        'limited time', 'verify now', 'suspended', 'locked',
        'within 24 hours', 'final notice', 'last chance']
    found_urgency = [w for w in urgency_words if w in email_body.lower()]
    if found_urgency:
        score += len(found_urgency) * 8
        indicators.append({
            'type': 'Urgency Language',
            'severity': 'High',
            'detail': f'Found urgency words: {", ".join(found_urgency)}',
            'score_impact': len(found_urgency) * 8
        })

    money_words = ['won', 'winner', 'prize', 'lottery', 'million',
        'bank account', 'wire transfer', 'western union',
        'gift card', 'bitcoin', 'inheritance', 'claim your']
    found_money = [w for w in money_words if w in email_body.lower()]
    if found_money:
        score += len(found_money) * 10
        indicators.append({
            'type': 'Financial Scam Keywords',
            'severity': 'High',
            'detail': f'Found: {", ".join(found_money)}',
            'score_impact': len(found_money) * 10
        })

    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_body)
    suspicious_url_indicators = []
    for url in urls:
        if any(x in url for x in ['-', 'secure', 'update',
                                   'verify', 'login', 'account',
                                   'confirm', 'unusual']):
            suspicious_url_indicators.append(url)
            score += 15
    if suspicious_url_indicators:
        indicators.append({
            'type': 'Suspicious URLs',
            'severity': 'Critical',
            'detail': f'Found suspicious URLs: {", ".join(suspicious_url_indicators[:3])}',
            'score_impact': len(suspicious_url_indicators) * 15
        })

    info_requests = ['password', 'social security', 'credit card',
        'bank details', 'date of birth', 'mother maiden',
        'pin number', 'account number', 'ssn']
    found_info = [w for w in info_requests if w in email_body.lower()]
    if found_info:
        score += len(found_info) * 20
        indicators.append({
            'type': 'Personal Information Request',
            'severity': 'Critical',
            'detail': f'Requesting sensitive data: {", ".join(found_info)}',
            'score_impact': len(found_info) * 20
        })

    grammar_patterns = ['dear customer', 'dear user', 'dear friend',
        'kindly do the needful', 'revert back',
        'do the needful', 'please to']
    found_grammar = [w for w in grammar_patterns if w in email_body.lower()]
    if found_grammar:
        score += 10
        indicators.append({
            'type': 'Generic/Poor Greeting',
            'severity': 'Medium',
            'detail': 'Non-personalized or suspicious greeting detected',
            'score_impact': 10
        })

    score = min(score, 100)

    if score >= 70:
        verdict = 'Almost Certainly Phishing'
    elif score >= 45:
        verdict = 'Likely Phishing — High Suspicion'
    elif score >= 25:
        verdict = 'Possibly Suspicious — Review Carefully'
    else:
        verdict = 'Likely Legitimate'

    is_phishing = score >= 45

    EmailContentScan.objects.create(
        email_body=email_body,
        phishing_score=score,
        verdict=verdict,
        is_phishing=is_phishing,
        indicators=indicators,
        urls_found=urls,
        keywords_found={
            'urgency': found_urgency,
            'money_scam': found_money,
            'info_requests': found_info,
            'grammar_issues': found_grammar,
        },
    )

    save_scan_history(
        user=request.user,
        scan_type='EMAIL',
        target='email-body',
        verdict='MALICIOUS' if is_phishing else 'SUSPICIOUS' if score >= 25 else 'SAFE',
        threat_score=score,
        engine='phishing-content-analyzer',
        metadata={
            'phishing_score': score,
            'indicator_count': len(indicators),
            'url_count': len(urls),
        },
    )

    return Response({
        'phishing_score': score,
        'verdict': verdict,
        'is_phishing': is_phishing,
        'indicators': indicators,
        'urls_found': urls,
        'total_indicators': len(indicators),
        'prediction_explanation': 'Score calculated based on urgency language, financial keywords, suspicious URLs, personal information requests, and grammar patterns',
    })
