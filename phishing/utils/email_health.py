import re
import socket
import time
import smtplib
import ipaddress
import dns.resolver
import dns.reversename
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed


BLACKLIST_ZONES = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org',
    'dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'web.dnsbl.sorbs.net',
    'dul.dnsbl.sorbs.net',
    'smtp.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'misc.dnsbl.sorbs.net',
    'http.dnsbl.sorbs.net',
    'block.dnsbl.sorbs.net',
    'zombie.dnsbl.sorbs.net',
    'rhsbl.sorbs.net',
    'badconf.rhsbl.sorbs.net',
    'nomail.rhsbl.sorbs.net',
    'black.uribl.com',
    'multi.uribl.com',
    'cbl.abuseat.org',
    'pbl.spamhaus.org',
    'xbl.spamhaus.org',
    'sbl.spamhaus.org',
    'ix.dnsbl.manitu.net',
    'truncate.gbudb.net',
    'db.wpbl.info',
    'bl.mailspike.net',
    'bl.blocklist.de',
    'dnsbl-1.uceprotect.net',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
]


def _dns_query(domain, record_type='A', timeout=5):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.exception.DNSException:
        return None


def _dns_query_txt(domain, timeout=5):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, 'TXT')
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.exception.DNSException:
        return None


def check_mx_records(domain):
    records = _dns_query(domain, 'MX')
    if records is None:
        return {'status': 'error', 'detail': 'DNS query failed', 'records': []}
    if not records:
        return {'status': 'missing', 'detail': 'No MX records found', 'records': []}

    mx_list = []
    for r in records:
        parts = r.split()
        if len(parts) >= 2:
            priority = int(parts[0])
            hostname = parts[1].rstrip('.')
            ips = _dns_query(hostname, 'A')
            mx_list.append({
                'priority': priority,
                'hostname': hostname,
                'ips': ips if ips else [],
                'response_time': None,
            })

    mx_list.sort(key=lambda x: x['priority'])

    for mx in mx_list:
        for ip in mx['ips']:
            start = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 25))
                sock.close()
                mx['response_time'] = round((time.time() - start) * 1000, 1)
            except (socket.timeout, ConnectionRefusedError, OSError):
                mx['response_time'] = None

    return {
        'status': 'ok',
        'detail': f'{len(mx_list)} MX record(s) found',
        'records': mx_list,
    }


def check_spf_record(domain):
    txt_records = _dns_query_txt(domain)
    if txt_records is None:
        return {'status': 'error', 'detail': 'DNS query failed', 'raw': ''}

    spf_raw = ''
    for txt in txt_records:
        if txt.startswith('v=spf1'):
            spf_raw = txt
            break

    if not spf_raw:
        return {'status': 'missing', 'detail': 'No SPF record found', 'raw': ''}

    issues = []
    mechanisms = []

    parts = spf_raw.split()
    for p in parts:
        if p.startswith('v='):
            continue
        mechanisms.append(p)

    has_hard_all = '-all' in mechanisms
    has_soft_all = '~all' in mechanisms
    has_neutral_all = '?all' in mechanisms
    has_redirect = any(m.startswith('redirect=') for m in mechanisms)
    include_count = sum(1 for m in mechanisms if m.startswith('include:'))

    if not has_hard_all and not has_soft_all and not has_neutral_all and not has_redirect:
        issues.append('No "all" mechanism: missing -all, ~all, ?all, or redirect')
    if include_count > 10:
        issues.append(f'Excessive DNS lookups: {include_count} includes (max 10)')
    if not include_count and not has_redirect:
        ip4_count = sum(1 for m in mechanisms if m.startswith('ip4:'))
        ip6_count = sum(1 for m in mechanisms if m.startswith('ip6:'))
        if not ip4_count and not ip6_count:
            issues.append('No ip4 or ip6 mechanisms: no authorized senders defined')

    result = 'hardfail' if has_hard_all else 'softfail' if has_soft_all else 'neutral' if has_neutral_all else 'pass'
    if has_redirect:
        result = 'redirect'

    return {
        'status': 'ok',
        'raw': spf_raw,
        'result': result,
        'mechanisms': mechanisms,
        'include_count': include_count,
        'has_hard_all': has_hard_all,
        'has_soft_all': has_soft_all,
        'has_neutral_all': has_neutral_all,
        'has_redirect': has_redirect,
        'issues': issues,
        'detail': 'SPF record found' if not issues else f'{len(issues)} issue(s) found',
    }


def check_dmarc_record(domain):
    dmarc_domain = f'_dmarc.{domain}'
    txt_records = _dns_query_txt(dmarc_domain)
    if txt_records is None:
        return {'status': 'error', 'detail': 'DNS query failed', 'raw': ''}

    dmarc_raw = ''
    for txt in txt_records:
        if txt.startswith('v=DMARC1'):
            dmarc_raw = txt
            break

    if not dmarc_raw:
        return {'status': 'missing', 'detail': 'No DMARC record found', 'raw': '', 'policy': 'none'}

    policy = 'none'
    subdomain_policy = None
    pct = 100
    rua = ''
    ruf = ''
    aspf = ''
    adkim = ''
    fo = ''
    issues = []

    for part in dmarc_raw.split(';'):
        part = part.strip()
        if part.startswith('v='):
            continue
        if part.startswith('p='):
            policy = part[2:].strip().lower()
            if policy not in ('none', 'quarantine', 'reject'):
                issues.append(f'Invalid policy value: {policy}')
                policy = 'none'
        elif part.startswith('sp='):
            subdomain_policy = part[3:].strip().lower()
        elif part.startswith('pct='):
            try:
                pct = int(part[4:].strip())
                if pct < 0 or pct > 100:
                    issues.append('pct must be between 0 and 100')
            except ValueError:
                issues.append('Invalid pct value')
        elif part.startswith('rua='):
            rua = part[4:].strip()
        elif part.startswith('ruf='):
            ruf = part[5:].strip()
        elif part.startswith('aspf='):
            aspf = part[5:].strip().lower()
        elif part.startswith('adkim='):
            adkim = part[6:].strip().lower()
        elif part.startswith('fo='):
            fo = part[3:].strip()

    if policy == 'none':
        issues.append('Policy is "none" — DMARC only monitors, no enforcement')

    return {
        'status': 'ok',
        'raw': dmarc_raw,
        'policy': policy,
        'subdomain_policy': subdomain_policy or policy,
        'pct': pct,
        'rua': rua,
        'ruf': ruf,
        'aspf': aspf,
        'adkim': adkim,
        'fo': fo,
        'issues': issues,
        'detail': f'DMARC policy: {policy}'
                  + (f' (subdomain: {subdomain_policy})' if subdomain_policy else ''),
    }


def check_dkim_record(domain, selector='default'):
    dkim_domain = f'{selector}._domainkey.{domain}'
    txt_records = _dns_query_txt(dkim_domain)

    if txt_records is None:
        return {'status': 'error', 'detail': 'DNS query failed', 'selector': selector}

    if not txt_records:
        alt_selector = 'selector1'
        alt_domain = f'{alt_selector}._domainkey.{domain}'
        alt_records = _dns_query_txt(alt_domain)
        if alt_records:
            return {
                'status': 'ok',
                'detail': 'DKIM record found',
                'selector': alt_selector,
                'records': alt_records,
            }
        return {'status': 'missing', 'detail': f'No DKIM record for selector "{selector}"', 'selector': selector}

    return {
        'status': 'ok',
        'detail': 'DKIM record found',
        'selector': selector,
        'records': txt_records,
    }


def _check_single_blacklist(ip, zone):
    reversed_octets = ip.split('.')
    reversed_ip = '.'.join(reversed(reversed_octets))
    query = f'{reversed_ip}.{zone}'
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(query, 'A')
        return {
            'zone': zone,
            'listed': True,
            'detail': f'Listed (returned: {", ".join(str(r) for r in answers)})',
        }
    except dns.resolver.NXDOMAIN:
        return {'zone': zone, 'listed': False, 'detail': 'Not listed'}
    except dns.resolver.NoAnswer:
        return {'zone': zone, 'listed': False, 'detail': 'Not listed'}
    except dns.exception.Timeout:
        return {'zone': zone, 'listed': False, 'detail': 'Timeout'}
    except dns.exception.DNSException:
        return {'zone': zone, 'listed': False, 'detail': 'Error'}
    except Exception:
        return {'zone': zone, 'listed': False, 'detail': 'Error'}


def check_blacklists(domain, ip=None):
    if ip:
        ip_to_check = ip
    else:
        mx = check_mx_records(domain)
        if mx['status'] == 'ok' and mx['records']:
            mx_records = [r for r in mx['records'] if r.get('ips')]
            if mx_records:
                ip_to_check = mx_records[0]['ips'][0]
            else:
                return {'status': 'error', 'detail': 'Could not resolve MX to IP', 'results': []}
        else:
            return {'status': 'error', 'detail': 'No MX records for domain', 'results': []}

    results = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_check_single_blacklist, ip_to_check, zone): zone for zone in BLACKLIST_ZONES}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                zone = futures[future]
                results.append({'zone': zone, 'listed': False, 'detail': 'Error'})

    results.sort(key=lambda x: x['zone'])
    listed_count = sum(1 for r in results if r['listed'])

    return {
        'status': 'ok',
        'ip_checked': ip_to_check,
        'total': len(results),
        'listed_count': listed_count,
        'clean_count': len(results) - listed_count,
        'results': results,
        'detail': f'{listed_count}/{len(results)} blacklists have this IP listed',
    }


def check_ptr_record(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {'status': 'error', 'detail': 'Invalid IP address'}

    try:
        rev_name = dns.reversename.from_address(ip)
        answers = _dns_query(str(rev_name), 'PTR')
        if answers:
            hostnames = [a.rstrip('.') for a in answers]
            hostname = hostnames[0]

            forward_ips = _dns_query(hostname, 'A')
            forward_match = ip in forward_ips if forward_ips else False

            return {
                'status': 'ok',
                'ip': ip,
                'hostname': hostname,
                'hostnames': hostnames,
                'forward_confirms': forward_match,
                'detail': f'PTR resolves to {hostname}'
                          + (' (forward confirmed)' if forward_match else ' (forward mismatch)'),
            }
        return {'status': 'missing', 'ip': ip, 'detail': 'No PTR record found', 'hostname': ''}
    except dns.exception.DNSException:
        return {'status': 'error', 'ip': ip, 'detail': 'DNS query failed', 'hostname': ''}


def check_smtp_banner(domain):
    mx = check_mx_records(domain)
    if mx['status'] != 'ok' or not mx['records']:
        return {'status': 'error', 'detail': 'No MX records to connect to'}

    for mx_record in mx['records'][:3]:
        for ip in mx_record.get('ips', []):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, 25))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()

                issues = []
                if not banner:
                    issues.append('Empty banner')
                elif '220' not in banner:
                    issues.append('Banner does not start with expected 220 code')
                if mx_record['hostname'].lower() not in banner.lower():
                    issues.append('Banner hostname does not match MX hostname')
                if 'nmap' in banner.lower() or 'exim' in banner.lower():
                    issues.append('Potentially revealing server info in banner')

                return {
                    'status': 'ok',
                    'banner': banner,
                    'server': mx_record['hostname'],
                    'ip': ip,
                    'issues': issues,
                    'detail': f'Connected to {mx_record["hostname"]} [{ip}]:25'
                              + (f' ({len(issues)} issue(s))' if issues else ''),
                }
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                continue

    return {'status': 'error', 'detail': 'Could not connect to any MX server on port 25'}


def calculate_health_score(mx, spf, dkim, dmarc, blacklists, ptr, smtp):
    breakdown = {}
    total = 0

    mx_score = 30
    if mx['status'] == 'ok':
        count = len(mx.get('records', []))
        if count == 0:
            mx_score = 0
        elif count > 3:
            mx_score = 25
        elif count >= 2:
            mx_score = 30
        else:
            mx_score = 20
        has_redundant = any(r.get('response_time') is not None for r in mx.get('records', []))
        if not has_redundant:
            mx_score = max(0, mx_score - 10)
    elif mx['status'] == 'missing':
        mx_score = 0
    else:
        mx_score = 5
    breakdown['mx'] = {'score': mx_score, 'max': 30, 'label': 'MX Records'}
    total += mx_score

    spf_score = 25
    if spf['status'] == 'ok':
        if spf.get('issues'):
            spf_score -= min(len(spf['issues']) * 5, 15)
        if spf.get('has_hard_all'):
            spf_score += 5
        elif spf.get('has_soft_all'):
            spf_score += 2
        else:
            spf_score -= 3
        spf_score = max(0, min(25, spf_score))
    elif spf['status'] == 'missing':
        spf_score = 0
    else:
        spf_score = 3
    breakdown['spf'] = {'score': spf_score, 'max': 25, 'label': 'SPF'}
    total += spf_score

    dkim_score = 15
    if dkim.get('status') == 'ok':
        dkim_score = 15
    elif dkim.get('status') == 'missing':
        dkim_score = 0
    else:
        dkim_score = 2
    breakdown['dkim'] = {'score': dkim_score, 'max': 15, 'label': 'DKIM'}
    total += dkim_score

    dmarc_score = 15
    if dmarc['status'] == 'ok':
        policy = dmarc.get('policy', 'none')
        if policy == 'reject':
            dmarc_score = 15
        elif policy == 'quarantine':
            dmarc_score = 12
        else:
            dmarc_score = 5
        if dmarc.get('issues'):
            dmarc_score -= min(len(dmarc['issues']) * 3, 10)
        dmarc_score = max(0, dmarc_score)
    elif dmarc['status'] == 'missing':
        dmarc_score = 0
    else:
        dmarc_score = 2
    breakdown['dmarc'] = {'score': dmarc_score, 'max': 15, 'label': 'DMARC'}
    total += dmarc_score

    bl_score = 15
    if blacklists['status'] == 'ok':
        listed = blacklists.get('listed_count', 0)
        if listed == 0:
            bl_score = 15
        elif listed <= 2:
            bl_score = 10
        elif listed <= 5:
            bl_score = 5
        else:
            bl_score = 0
    elif blacklists['status'] == 'error':
        bl_score = 7
    breakdown['blacklists'] = {'score': bl_score, 'max': 15, 'label': 'Blacklists'}
    total += bl_score

    ptr_score = 10
    if ptr['status'] == 'ok':
        if ptr.get('forward_confirms'):
            ptr_score = 10
        else:
            ptr_score = 5
    elif ptr['status'] == 'missing':
        ptr_score = 2
    else:
        ptr_score = 0
    breakdown['ptr'] = {'score': ptr_score, 'max': 10, 'label': 'PTR Record'}
    total += ptr_score

    smtp_score = 5
    if smtp['status'] == 'ok':
        if smtp.get('issues'):
            smtp_score = 2
        else:
            smtp_score = 5
    else:
        smtp_score = 0
    breakdown['smtp'] = {'score': smtp_score, 'max': 5, 'label': 'SMTP Banner'}
    total += smtp_score

    total = max(0, min(100, total))
    return total, breakdown


def get_health_rating(score):
    if score >= 90:
        return 'excellent'
    elif score >= 70:
        return 'good'
    elif score >= 50:
        return 'fair'
    elif score >= 30:
        return 'poor'
    else:
        return 'critical'
