import json
import re
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from .models import EmailHeaderScan, EmailHealthCheck, SuspiciousEmailReport
from .utils.header_parser import (
    parse_email_headers,
    extract_all_ips,
    trace_email_path,
    check_spf,
    check_dkim,
    check_dmarc,
    check_ip_reputation,
    detect_spoofing,
    calculate_threat_score,
    get_threat_level,
)
from .utils.email_health import (
    check_mx_records,
    check_spf_record,
    check_dmarc_record,
    check_dkim_record,
    check_blacklists,
    check_ptr_record,
    check_smtp_banner,
    calculate_health_score,
    get_health_rating,
)


@login_required
def email_health_view(request):
    result = None
    domain = ''

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        domain = domain.split('@')[-1]

        if not domain:
            messages.error(request, _('Please enter a valid domain name.'))
            return render(request, 'phishing/email_health.html')

        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$', domain):
            messages.error(request, _('Please enter a valid domain name.'))
            return render(request, 'phishing/email_health.html')

        try:
            mx = check_mx_records(domain)
            spf = check_spf_record(domain)
            dmarc_res = check_dmarc_record(domain)
            dkim = check_dkim_record(domain)
            dkim2 = check_dkim_record(domain, 'google')
            dkim_results = [dkim]
            if dkim2['status'] == 'ok':
                dkim_results.append(dkim2)

            blacklists = check_blacklists(domain)
            ptr_domains = []
            if mx['status'] == 'ok':
                for rec in mx.get('records', []):
                    for ip in rec.get('ips', []):
                        ptr = check_ptr_record(ip)
                        ptr_domains.append(ptr)
                        break
                    if ptr_domains:
                        break
            ptr = ptr_domains[0] if ptr_domains else check_ptr_record('')

            smtp = check_smtp_banner(domain)

            health_score, score_breakdown = calculate_health_score(
                mx, spf, dkim, dmarc_res, blacklists, ptr, smtp,
            )
            health_rating = get_health_rating(health_score)

            check = EmailHealthCheck.objects.create(
                user=request.user,
                domain=domain,
                mx_records=mx.get('records', []),
                spf_result=spf,
                dkim_results=dkim_results,
                dmarc_result=dmarc_res,
                blacklist_results=blacklists.get('results', []),
                ptr_result=ptr,
                smtp_banner=smtp.get('banner', ''),
                health_score=health_score,
                score_breakdown=score_breakdown,
            )

            result = {
                'domain': domain,
                'mx': mx,
                'spf': spf,
                'dkim_results': dkim_results,
                'dmarc': dmarc_res,
                'blacklists': blacklists,
                'ptr': ptr,
                'smtp': smtp,
                'health_score': health_score,
                'health_rating': health_rating,
                'score_breakdown': score_breakdown,
            }

            messages.success(request, _(f'Health check complete for {domain}!'))

        except Exception as e:
            messages.error(request, _(f'Error checking domain: {str(e)}'))

    context = {
        'result': result,
        'domain': domain,
        'BLACKLIST_ZONES': [
            'zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org',
            'dnsbl.sorbs.net', 'spam.dnsbl.sorbs.net', 'dul.dnsbl.sorbs.net',
            'cbl.abuseat.org', 'pbl.spamhaus.org', 'xbl.spamhaus.org',
            'sbl.spamhaus.org', 'bl.mailspike.net', 'bl.blocklist.de',
        ],
    }
    return render(request, 'phishing/email_health.html', context)


@login_required
def suspicious_email_view(request):
    result = None
    report = None

    if request.method == 'POST':
        subject = request.POST.get('subject', '').strip()
        sender_email = request.POST.get('sender_email', '').strip()
        email_body = request.POST.get('email_body', '').strip()
        raw_email = request.POST.get('raw_email', '').strip()

        if not sender_email:
            messages.error(request, _('Sender email is required.'))
            return render(request, 'phishing/suspicious_email.html')

        import re as _re
        if not _re.match(r'[^@]+@[^@]+\.[^@]+', sender_email):
            messages.error(request, _('Please enter a valid sender email address.'))
            return render(request, 'phishing/suspicious_email.html')

        if not email_body and not raw_email:
            messages.error(request, _('Please provide email body or raw email content.'))
            return render(request, 'phishing/suspicious_email.html')

        try:
            from .utils.email_analyzer import analyze_suspicious_email
            analysis = analyze_suspicious_email(subject, sender_email, email_body or raw_email, raw_email)

            report = SuspiciousEmailReport.objects.create(
                user=request.user,
                email_subject=subject,
                sender_email=sender_email,
                sender_domain=analysis['sender_domain'],
                email_body=email_body or raw_email,
                attachments_info=analysis.get('email_structure', {}),
                links_found=analysis['links'],
                phishing_indicators=analysis['indicators'],
                risk_score=analysis['risk_score'],
                verdict=analysis['verdict'],
            )

            result = analysis

            messages.success(request, _(f'Analysis complete — verdict: {analysis["verdict"].upper()}'))

        except Exception as e:
            messages.error(request, _(f'Error analyzing email: {str(e)}'))

    context = {
        'result': result,
        'report': report,
        'html_tricks': result.get('html_tricks', []) if result else None,
    }
    return render(request, 'phishing/suspicious_email.html', context)


@login_required
def header_analyzer_view(request):
    scan = None
    result = None
    hops = None
    ips = None
    spf = None
    dkim = None
    dmarc = None
    ip_reputations = None
    spoofing_issues = None
    threat_score = None
    threat_level = None

    if request.method == 'POST':
        raw_headers = request.POST.get('raw_headers', '').strip()
        if not raw_headers:
            messages.error(request, _('Please paste email headers to analyze.'))
            return render(request, 'phishing/header_analyzer.html')

        try:
            parsed = parse_email_headers(raw_headers)
            hops = trace_email_path(parsed)
            ips = extract_all_ips(parsed)

            from_domain = ''
            from_email = parsed.get('_from_email', '')
            if '@' in from_email:
                from_domain = from_email.split('@')[-1]

            spf = check_spf(from_domain)
            dkim = check_dkim(from_domain)
            dmarc = check_dmarc(from_domain)

            ip_reputations = []
            for ip_addr in ips:
                rep = check_ip_reputation(ip_addr)
                ip_reputations.append(rep)

            spoofing_issues = detect_spoofing(parsed)
            threat_score = calculate_threat_score(spf, dkim, dmarc, spoofing_issues, ip_reputations)
            threat_level = get_threat_level(threat_score)

            sender_ip = ips[0] if ips else None

            parsed_copy = {k: v for k, v in parsed.items()}
            if '_raw_headers' in parsed_copy:
                del parsed_copy['_raw_headers']

            scan = EmailHeaderScan.objects.create(
                user=request.user,
                raw_headers=raw_headers,
                parsed_json=parsed_copy,
                sender_ip=sender_ip,
                spf_result=spf.get('result', 'error'),
                dkim_result=dkim.get('result', 'error'),
                dmarc_result=dmarc.get('result', 'error'),
                routing_hops=hops,
                threat_score=threat_score,
            )

            messages.success(request, _('Header analysis complete!'))

            result = {
                'parsed': parsed_copy,
                'hops': hops,
                'ips': ips,
                'spf': spf,
                'dkim': dkim,
                'dmarc': dmarc,
                'ip_reputations': ip_reputations,
                'spoofing_issues': spoofing_issues,
                'threat_score': threat_score,
                'threat_level': threat_level,
                'from_email': from_email,
                'from_domain': from_domain,
            }

        except Exception as e:
            messages.error(request, _(f'Error analyzing headers: {str(e)}'))

    context = {
        'scan': scan,
        'result': result,
        'hops': hops,
        'ips': ips,
        'spf': spf,
        'dkim': dkim,
        'dmarc': dmarc,
        'ip_reputations': ip_reputations,
        'spoofing_issues': spoofing_issues,
        'threat_score': threat_score,
        'threat_level': threat_level,
        'parsed_json': json.dumps(scan.parsed_json, indent=2) if scan else None,
    }

    return render(request, 'phishing/header_analyzer.html', context)
