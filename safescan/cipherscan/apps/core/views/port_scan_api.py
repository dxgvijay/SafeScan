import json
import socket
import threading
import time
import ipaddress
import uuid

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

from apps.accounts.utils.scan_history_helper import save_scan_history


PORT_SERVICES = {
    20: {"name": "FTP-data", "service": "FTP Data Transfer", "protocol": "TCP"},
    21: {"name": "FTP", "service": "File Transfer Protocol", "protocol": "TCP"},
    22: {"name": "SSH", "service": "Secure Shell", "protocol": "TCP"},
    23: {"name": "Telnet", "service": "Telnet", "protocol": "TCP"},
    25: {"name": "SMTP", "service": "Simple Mail Transfer", "protocol": "TCP"},
    53: {"name": "DNS", "service": "Domain Name System", "protocol": "TCP/UDP"},
    80: {"name": "HTTP", "service": "Hypertext Transfer Protocol", "protocol": "TCP"},
    110: {"name": "POP3", "service": "Post Office Protocol v3", "protocol": "TCP"},
    135: {"name": "RPC", "service": "Remote Procedure Call", "protocol": "TCP"},
    137: {"name": "NetBIOS", "service": "NetBIOS Name Service", "protocol": "TCP/UDP"},
    139: {"name": "SMB", "service": "NetBIOS Session Service", "protocol": "TCP"},
    143: {"name": "IMAP", "service": "Internet Message Access Protocol", "protocol": "TCP"},
    389: {"name": "LDAP", "service": "Lightweight Directory Access", "protocol": "TCP"},
    443: {"name": "HTTPS", "service": "HTTP over TLS", "protocol": "TCP"},
    445: {"name": "SMB", "service": "Windows File Sharing", "protocol": "TCP"},
    465: {"name": "SMTPS", "service": "SMTP over SSL", "protocol": "TCP"},
    514: {"name": "Syslog", "service": "System Logging", "protocol": "TCP/UDP"},
    587: {"name": "SMTP", "service": "SMTP Submission", "protocol": "TCP"},
    636: {"name": "LDAPS", "service": "LDAP over SSL", "protocol": "TCP"},
    993: {"name": "IMAPS", "service": "IMAP over SSL", "protocol": "TCP"},
    995: {"name": "POP3S", "service": "POP3 over SSL", "protocol": "TCP"},
    1025: {"name": "NFS", "service": "NFS or IIS", "protocol": "TCP"},
    1080: {"name": "SOCKS", "service": "SOCKS Proxy", "protocol": "TCP"},
    1194: {"name": "OpenVPN", "service": "OpenVPN", "protocol": "TCP/UDP"},
    1352: {"name": "Lotus", "service": "IBM Lotus Notes", "protocol": "TCP"},
    1433: {"name": "MSSQL", "service": "Microsoft SQL Server", "protocol": "TCP"},
    1434: {"name": "MSSQL", "service": "MS SQL Monitor", "protocol": "TCP"},
    1521: {"name": "Oracle", "service": "Oracle Database", "protocol": "TCP"},
    2049: {"name": "NFS", "service": "Network File System", "protocol": "TCP"},
    2082: {"name": "cPanel", "service": "cPanel", "protocol": "TCP"},
    2083: {"name": "cPanel", "service": "cPanel SSL", "protocol": "TCP"},
    2181: {"name": "ZooKeeper", "service": "Apache ZooKeeper", "protocol": "TCP"},
    2375: {"name": "Docker", "service": "Docker REST API", "protocol": "TCP"},
    2376: {"name": "Docker", "service": "Docker TLS", "protocol": "TCP"},
    2483: {"name": "Oracle", "service": "Oracle DB", "protocol": "TCP"},
    2484: {"name": "Oracle", "service": "Oracle DB SSL", "protocol": "TCP"},
    3128: {"name": "Squid", "service": "Squid Proxy", "protocol": "TCP"},
    3306: {"name": "MySQL", "service": "MySQL Database", "protocol": "TCP"},
    3389: {"name": "RDP", "service": "Remote Desktop Protocol", "protocol": "TCP"},
    3690: {"name": "SVN", "service": "Apache Subversion", "protocol": "TCP"},
    4000: {"name": "ICQ", "service": "ICQ", "protocol": "TCP"},
    4333: {"name": "mSQL", "service": "mini SQL", "protocol": "TCP"},
    4500: {"name": "IPsec", "service": "IPsec NAT-T", "protocol": "TCP/UDP"},
    4848: {"name": "GlassFish", "service": "GlassFish Admin", "protocol": "TCP"},
    5000: {"name": "Flask", "service": "Flask Dev / UPnP", "protocol": "TCP"},
    5432: {"name": "PostgreSQL", "service": "PostgreSQL Database", "protocol": "TCP"},
    5555: {"name": "ADB", "service": "Android Debug Bridge", "protocol": "TCP"},
    5632: {"name": "pcAnywhere", "service": "pcAnywhere", "protocol": "TCP"},
    5800: {"name": "VNC", "service": "VNC HTTP", "protocol": "TCP"},
    5900: {"name": "VNC", "service": "VNC Remote Desktop", "protocol": "TCP"},
    5984: {"name": "CouchDB", "service": "Apache CouchDB", "protocol": "TCP"},
    5985: {"name": "WinRM", "service": "Windows Remote Mgmt", "protocol": "TCP"},
    5986: {"name": "WinRM", "service": "WinRM SSL", "protocol": "TCP"},
    6000: {"name": "X11", "service": "X Window System", "protocol": "TCP"},
    6379: {"name": "Redis", "service": "Redis Key-Value Store", "protocol": "TCP"},
    6443: {"name": "Kubernetes", "service": "Kubernetes API", "protocol": "TCP"},
    6660: {"name": "IRC", "service": "Internet Relay Chat", "protocol": "TCP"},
    6667: {"name": "IRC", "service": "Internet Relay Chat", "protocol": "TCP"},
    7001: {"name": "WebLogic", "service": "Oracle WebLogic", "protocol": "TCP"},
    7070: {"name": "RTSP", "service": "Real Time Streaming", "protocol": "TCP"},
    8000: {"name": "HTTP", "service": "HTTP Alternate", "protocol": "TCP"},
    8008: {"name": "HTTP", "service": "HTTP Alternate", "protocol": "TCP"},
    8080: {"name": "HTTP Proxy", "service": "HTTP Proxy / Tomcat", "protocol": "TCP"},
    8081: {"name": "HTTP", "service": "HTTP Proxy / McAfee", "protocol": "TCP"},
    8443: {"name": "HTTPS", "service": "HTTPS Alternate", "protocol": "TCP"},
    8444: {"name": "HTTPS", "service": "HTTPS Alternate", "protocol": "TCP"},
    8500: {"name": "Consul", "service": "HashiCorp Consul", "protocol": "TCP"},
    8834: {"name": "Nessus", "service": "Nessus Scanner", "protocol": "TCP"},
    8888: {"name": "HTTP", "service": "HTTP Alternate", "protocol": "TCP"},
    9000: {"name": "SonarQube", "service": "SonarQube / PHP-FPM", "protocol": "TCP"},
    9042: {"name": "Cassandra", "service": "Apache Cassandra", "protocol": "TCP"},
    9092: {"name": "Kafka", "service": "Apache Kafka", "protocol": "TCP"},
    9100: {"name": "Printer", "service": "JetDirect Printing", "protocol": "TCP"},
    9200: {"name": "Elasticsearch", "service": "Elasticsearch", "protocol": "TCP"},
    9300: {"name": "Elasticsearch", "service": "Elasticsearch Cluster", "protocol": "TCP"},
    9418: {"name": "Git", "service": "Git", "protocol": "TCP"},
    9999: {"name": "Abyss", "service": "Abyss Web / Xine", "protocol": "TCP"},
    10000: {"name": "Webmin", "service": "Webmin Admin", "protocol": "TCP"},
    11211: {"name": "Memcached", "service": "Memcached", "protocol": "TCP"},
    27017: {"name": "MongoDB", "service": "MongoDB Database", "protocol": "TCP"},
    27018: {"name": "MongoDB", "service": "MongoDB Shard", "protocol": "TCP"},
    28017: {"name": "MongoDB", "service": "MongoDB Web Status", "protocol": "TCP"},
    50070: {"name": "Hadoop", "service": "Hadoop NameNode", "protocol": "TCP"},
    50075: {"name": "Hadoop", "service": "Hadoop DataNode", "protocol": "TCP"},
}

DANGEROUS_PORTS = {
    21: {"risk": "high", "desc": "FTP transmits credentials in cleartext. Use SFTP or SCP instead."},
    23: {"risk": "critical", "desc": "Telnet transmits all data in cleartext including passwords. Use SSH instead."},
    25: {"risk": "high", "desc": "SMTP can be abused for email spoofing and spam relay if misconfigured."},
    53: {"risk": "medium", "desc": "DNS servers can be exploited for amplification DDoS attacks if open to the internet."},
    110: {"risk": "high", "desc": "POP3 transmits credentials in cleartext. Use POP3S instead."},
    135: {"risk": "critical", "desc": "MS RPC is frequently exploited by worms and malware. Block at firewall."},
    139: {"risk": "critical", "desc": "NetBIOS exposes system information. Should not be exposed to the internet."},
    143: {"risk": "high", "desc": "IMAP transmits credentials in cleartext. Use IMAPS instead."},
    389: {"risk": "high", "desc": "LDAP transmits data in cleartext. Use LDAPS on port 636 instead."},
    445: {"risk": "critical", "desc": "SMB is targeted by ransomware (EternalBlue, WannaCry). Never expose to internet."},
    514: {"risk": "medium", "desc": "Syslog may leak system log information if accessible."},
    636: {"risk": "low", "desc": "LDAPS is encrypted but should still be access-controlled."},
    993: {"risk": "low", "desc": "IMAPS is encrypted, but verify TLS configuration."},
    995: {"risk": "low", "desc": "POP3S is encrypted, but verify TLS configuration."},
    1433: {"risk": "high", "desc": "MSSQL should not be exposed to the internet. Use VPN for remote access."},
    1521: {"risk": "high", "desc": "Oracle DB should not be internet-facing without proper access controls."},
    2049: {"risk": "high", "desc": "NFS can expose file systems if not properly secured."},
    2375: {"risk": "critical", "desc": "Docker API without TLS gives full root access to host."},
    3128: {"risk": "medium", "desc": "Open proxy can be abused for anonymous internet access."},
    3306: {"risk": "high", "desc": "MySQL should not be exposed to the internet. Use SSH tunneling."},
    3389: {"risk": "critical", "desc": "RDP is heavily targeted by ransomware attacks. Use VPN or RD Gateway."},
    5432: {"risk": "high", "desc": "PostgreSQL should not be exposed to the internet without proper access controls."},
    5900: {"risk": "high", "desc": "VNC often lacks proper authentication. Use SSH tunneling."},
    6379: {"risk": "high", "desc": "Redis can be exploited if not properly secured with authentication."},
    8080: {"risk": "medium", "desc": "HTTP proxy can be abused if open to the internet."},
    8443: {"risk": "low", "desc": "HTTPS alternate port. Verify TLS configuration."},
    9200: {"risk": "high", "desc": "Elasticsearch can expose data if not access-controlled."},
    11211: {"risk": "high", "desc": "Memcached used in amplification DDoS attacks. Should not be internet-facing."},
    27017: {"risk": "high", "desc": "MongoDB should not be exposed without authentication enabled."},
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 636,
    993, 995, 1025, 1080, 1194, 1352, 1433, 1434, 1521, 2049, 2082, 2083, 2181, 2375,
    2376, 3128, 3306, 3389, 3690, 4000, 4333, 4500, 4848, 5000, 5432, 5555, 5632, 5800,
    5900, 5984, 5985, 5986, 6000, 6379, 6443, 7001, 7070, 8000, 8008, 8080, 8081, 8443,
    8444, 8500, 8834, 8888, 9000, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 11211,
    27017, 27018, 28017, 50070, 50075,
]

TOP_100_PORTS = [
    80, 23, 22, 21, 3389, 110, 443, 445, 139, 135, 143, 993, 995, 389, 25, 53, 636, 465,
    587, 8080, 8443, 3306, 5432, 5900, 1433, 1521, 6379, 27017, 2049, 11211, 9200, 8444,
    8000, 10000, 2082, 2083, 22, 3128, 6000, 6667, 7001, 7070, 8008, 8081, 8444, 8500,
    8834, 8888, 9000, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 11211, 27017,
    27018, 28017, 50070, 50075, 1025, 1080, 1194, 1352, 1434, 2483, 2484, 3690, 4000,
    4333, 4500, 4848, 5000, 5555, 5632, 5800, 5984, 5985, 5986, 6443, 2181, 2375, 2376,
    514, 111, 1026, 1027, 1028, 1029, 1030, 1723, 1701, 5060, 5061, 5222, 5269, 8089,
    9090, 9443,
]


def _parse_ports(port_spec):
    if port_spec == "common":
        return COMMON_PORTS
    if port_spec == "top100":
        return TOP_100_PORTS
    if port_spec == "all":
        return list(range(1, 65536))

    try:
        return [int(port_spec.strip())]
    except (ValueError, AttributeError):
        pass

    if "," in port_spec:
        ports = []
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                a, b = int(a.strip()), int(b.strip())
                ports.extend(range(a, b + 1))
            else:
                ports.append(int(part))
        return ports

    if "-" in port_spec:
        a, b = port_spec.split("-", 1)
        return list(range(int(a.strip()), int(b.strip())))

    raise ValueError(f"Invalid port specification: {port_spec}")


def _resolve_target(target):
    try:
        ipaddress.ip_address(target)
        return target, "ip"
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, "hostname"
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {target}")


def _is_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def _get_service_banner(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.settimeout(1)
        banner = b""
        try:
            banner = s.recv(1024)
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        s.close()
        if banner:
            try:
                return banner.decode("utf-8", errors="replace").strip()[:100]
            except Exception:
                return None
        return None
    except Exception:
        return None


def _get_risk_level(port):
    info = DANGEROUS_PORTS.get(port)
    if info:
        return info
    if port < 1024:
        return {"risk": "low", "desc": "Well-known system port. Should be access-controlled."}
    if port < 49152:
        return {"risk": "info", "desc": "Registered port used by user applications."}
    return {"risk": "info", "desc": "Dynamic/private port. Typically used for ephemeral connections."}


def _scan_port(host, port, timeout):
    result = {
        "port": port,
        "state": "unknown",
        "service_name": None,
        "service_desc": None,
        "protocol": "TCP",
        "banner": None,
        "latency_ms": None,
        "risk": None,
        "risk_desc": None,
    }

    service_info = PORT_SERVICES.get(port)
    if service_info:
        result["service_name"] = service_info["name"]
        result["service_desc"] = service_info["service"]
        result["protocol"] = service_info["protocol"]

    risk_info = _get_risk_level(port)
    result["risk"] = risk_info.get("risk", "info")
    result["risk_desc"] = risk_info.get("desc", "")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        code = s.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        result["latency_ms"] = round(elapsed, 1)

        if code == 0:
            result["state"] = "open"
            banner = _get_service_banner(host, port, timeout=0.5)
            if banner:
                result["banner"] = banner
        elif code == socket.errno.ECONNREFUSED:
            result["state"] = "closed"
        elif code == socket.errno.EHOSTUNREACH:
            result["state"] = "filtered"
        elif code == socket.errno.ENETUNREACH:
            result["state"] = "filtered"
        elif code == socket.errno.ETIMEDOUT:
            result["state"] = "filtered"
        else:
            result["state"] = "filtered"
        s.close()
    except socket.timeout:
        result["state"] = "filtered"
    except (socket.gaierror, OSError, ConnectionError) as e:
        result["state"] = "filtered"

    return result


SCAN_STORE = {}
SCAN_LOCK = threading.Lock()
SCAN_THREAD_TIMEOUT = 300


def _run_scan(scan_id, host, ports, timeout):
    total = len(ports)
    results = []
    start_time = time.time()

    for i, port in enumerate(ports):
        if time.time() - start_time > SCAN_THREAD_TIMEOUT:
            break

        result = _scan_port(host, port, timeout)
        results.append(result)

        with SCAN_LOCK:
            if scan_id in SCAN_STORE:
                SCAN_STORE[scan_id]["progress"] = i + 1
                SCAN_STORE[scan_id]["results"] = results
                SCAN_STORE[scan_id]["current_port"] = port

    duration = round((time.time() - start_time) * 1000, 1)
    open_ports = [r for r in results if r["state"] == "open"]
    closed_ports = [r for r in results if r["state"] == "closed"]
    filtered_ports = [r for r in results if r["state"] == "filtered"]

    with SCAN_LOCK:
        if scan_id in SCAN_STORE:
            SCAN_STORE[scan_id]["status"] = "completed"
            SCAN_STORE[scan_id]["results"] = results
            SCAN_STORE[scan_id]["progress"] = total
            SCAN_STORE[scan_id]["current_port"] = None
            SCAN_STORE[scan_id]["duration_ms"] = duration
            SCAN_STORE[scan_id]["open_count"] = len(open_ports)
            SCAN_STORE[scan_id]["closed_count"] = len(closed_ports)
            SCAN_STORE[scan_id]["filtered_count"] = len(filtered_ports)
            SCAN_STORE[scan_id]["total_scanned"] = len(results)

    # Save scan history
    scan_data = SCAN_STORE.get(scan_id, {})
    if scan_data.get("user_id"):
        try:
            from django.contrib.auth import get_user_model
            user = get_user_model().objects.get(id=scan_data["user_id"])
            save_scan_history(
                user=user,
                scan_type='PORT',
                target=scan_data.get("target", host),
                verdict='SUSPICIOUS' if open_ports else 'SAFE',
                threat_score=min(len(open_ports) * 10, 100),
                duration=int(duration),
                engine='port-scanner',
                metadata={
                    'host': host,
                    'ports_scanned': len(results),
                    'open_ports': len(open_ports),
                    'open_ports_list': [r['port'] for r in open_ports],
                },
            )
        except Exception:
            pass

    # Cleanup old scans
    _cleanup_old_scans()


def _cleanup_old_scans():
    now = time.time()
    with SCAN_LOCK:
        stale = [sid for sid, s in SCAN_STORE.items() if (now - s.get("created_at", 0)) > 600]
        for sid in stale:
            del SCAN_STORE[sid]


def _get_scan_report(scan_id):
    with SCAN_LOCK:
        return SCAN_STORE.get(scan_id)


@csrf_exempt
@require_http_methods(["POST"])
def port_scan_start_view(request):
    try:
        body = json.loads(request.body)
        target = body.get("target", "").strip()
        port_spec = body.get("ports", "common")
        timeout = min(float(body.get("timeout", 2)), 5)
        allow_private = body.get("allow_private", False)

        if not target:
            return JsonResponse({"error": "Target (IP or hostname) is required"}, status=400)

        resolved_ip, target_type = _resolve_target(target)

        if not allow_private and _is_private_ip(resolved_ip):
            return JsonResponse({
                "error": "Scanning private IP addresses is restricted",
                "detail": f"{resolved_ip} is a private address",
            }, status=400)

        ports = _parse_ports(port_spec)
        if not ports:
            return JsonResponse({"error": "No valid ports specified"}, status=400)

        ports = sorted(set(p for p in ports if 1 <= p <= 65535))
        if len(ports) > 500:
            return JsonResponse({"error": "Maximum of 500 ports per scan"}, status=400)

        scan_id = str(uuid.uuid4())
        user_id = request.user.id if request.user.is_authenticated else None
        scan_data = {
            "scan_id": scan_id,
            "status": "scanning",
            "target": target,
            "resolved_ip": resolved_ip,
            "target_type": target_type,
            "port_spec": port_spec,
            "total_ports": len(ports),
            "progress": 0,
            "current_port": None,
            "results": [],
            "open_count": 0,
            "closed_count": 0,
            "filtered_count": 0,
            "total_scanned": 0,
            "duration_ms": None,
            "created_at": time.time(),
            "user_id": user_id,
        }

        with SCAN_LOCK:
            SCAN_STORE[scan_id] = scan_data

        t = threading.Thread(
            target=_run_scan, args=(scan_id, resolved_ip, ports, timeout), daemon=True
        )
        t.start()

        return JsonResponse({
            "scan_id": scan_id,
            "status": "scanning",
            "target": target,
            "resolved_ip": resolved_ip,
            "target_type": target_type,
            "total_ports": len(ports),
        })

    except ValueError as e:
        return JsonResponse({"error": str(e)}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def port_scan_status_view(request, scan_id):
    scan = _get_scan_report(scan_id)
    if not scan:
        return JsonResponse({"error": "Scan not found"}, status=404)

    result = {
        "scan_id": scan["scan_id"],
        "status": scan["status"],
        "target": scan["target"],
        "resolved_ip": scan["resolved_ip"],
        "target_type": scan["target_type"],
        "total_ports": scan["total_ports"],
        "progress": scan["progress"],
        "current_port": scan["current_port"],
        "open_count": scan["open_count"],
        "closed_count": scan["closed_count"],
        "filtered_count": scan["filtered_count"],
        "total_scanned": scan["total_scanned"],
        "duration_ms": scan["duration_ms"],
    }

    if scan["status"] == "completed":
        result["results"] = scan["results"]

    return JsonResponse(result)


@csrf_exempt
@require_http_methods(["GET"])
def port_scan_result_view(request, scan_id):
    scan = _get_scan_report(scan_id)
    if not scan:
        return JsonResponse({"error": "Scan not found"}, status=404)

    return JsonResponse(scan)


@csrf_exempt
@require_http_methods(["POST"])
def port_scan_export_view(request, scan_id):
    try:
        body = json.loads(request.body) if request.body else {}
        export_format = body.get("format", "json")
    except json.JSONDecodeError:
        export_format = "json"

    scan = _get_scan_report(scan_id)
    if not scan:
        return JsonResponse({"error": "Scan not found"}, status=404)

    if scan["status"] != "completed":
        return JsonResponse({"error": "Scan not yet completed"}, status=400)

    from django.http import HttpResponse

    if export_format == "json":
        data = json.dumps(scan, indent=2, default=str)
        return HttpResponse(data, content_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="port-scan-{scan_id[:8]}.json"'})

    if export_format == "csv":
        lines = ["port,state,service,protocol,latency_ms,risk,banner"]
        for r in scan["results"]:
            banner = (r.get("banner") or "").replace('"', '""')
            lines.append(f'{r["port"]},{r["state"]},{r.get("service_name") or ""},{r.get("protocol") or "TCP"},{r.get("latency_ms") or ""},{r.get("risk") or ""},"{banner}"')
        csv_content = "\n".join(lines)
        return HttpResponse(csv_content, content_type="text/csv",
                            headers={"Content-Disposition": f'attachment; filename="port-scan-{scan_id[:8]}.csv"'})

    lines = []
    lines.append("=" * 60)
    lines.append("CipherScan Port Scanner Report")
    lines.append("=" * 60)
    lines.append(f"Target: {scan['target']} ({scan['resolved_ip']})")
    lines.append(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Duration: {scan.get('duration_ms', 0)} ms")
    lines.append(f"Ports Scanned: {scan['total_scanned']}")
    lines.append(f"Open: {scan['open_count']} | Closed: {scan['closed_count']} | Filtered: {scan['filtered_count']}")
    lines.append("")
    lines.append("--- Open Ports ---")
    for r in scan["results"]:
        if r["state"] == "open":
            lines.append(f"  {r['port']}/tcp  {r.get('service_name', 'unknown'):<12} {r.get('latency_ms', '?'):>8} ms  risk={r.get('risk', 'info')}")
            if r.get("banner"):
                lines.append(f"    banner: {r['banner']}")
    if not [r for r in scan["results"] if r["state"] == "open"]:
        lines.append("  (none)")
    lines.append("")
    lines.append("--- Closed Ports ---")
    count = sum(1 for r in scan["results"] if r["state"] == "closed")
    lines.append(f"  {count} closed ports")
    lines.append("")
    lines.append("--- Filtered Ports ---")
    count = sum(1 for r in scan["results"] if r["state"] == "filtered")
    lines.append(f"  {count} filtered ports")
    lines.append("")
    lines.append("=" * 60)
    lines.append("Generated by CipherScan (https://cipherscan.app)")

    txt_content = "\n".join(lines)
    return HttpResponse(txt_content, content_type="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="port-scan-{scan_id[:8]}.txt"'})
