import json
import socket
import concurrent.futures
import hashlib
import time
import ipaddress

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

from apps.accounts.utils.scan_history_helper import save_scan_history


def _resolve_host(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


@csrf_exempt
@require_http_methods(["POST"])
def port_scan_view(request):
    try:
        data = json.loads(request.body)
        host = data.get("host", "").strip()
        port_start = int(data.get("port_start", 1))
        port_end = int(data.get("port_end", 1024))
        timeout_val = float(data.get("timeout", 1.0))

        if not host:
            return JsonResponse({"error": "Host is required"}, status=400)

        ip = _resolve_host(host)
        if not ip:
            return JsonResponse({"error": f"Cannot resolve host: {host}"}, status=400)

        port_start = max(1, min(port_start, 65535))
        port_end = max(port_start, min(port_end, 65535))
        timeout_val = max(0.1, min(timeout_val, 10.0))

        open_ports = []
        start_time = time.time()

        def _scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout_val)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    return port, service
                return None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(_scan_port, p): p for p in range(port_start, port_end + 1)}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append({"port": result[0], "service": result[1]})

        open_ports.sort(key=lambda x: x["port"])
        elapsed = round((time.time() - start_time) * 1000, 1)

        if request.user.is_authenticated:
            save_scan_history(
                user=request.user,
                scan_type='PORT',
                target=host,
                verdict='SUSPICIOUS' if open_ports else 'SAFE',
                threat_score=min(len(open_ports) * 10, 100),
                duration=int(elapsed),
                engine='sandbox-port-scanner',
                metadata={
                    'ip': ip,
                    'port_range': f'{port_start}-{port_end}',
                    'ports_scanned': port_end - port_start + 1,
                    'open_ports': len(open_ports),
                },
            )

        return JsonResponse({
            "host": host,
            "ip": ip,
            "port_range": f"{port_start}-{port_end}",
            "open_ports": open_ports,
            "total_scanned": port_end - port_start + 1,
            "open_count": len(open_ports),
            "duration_ms": elapsed,
        })

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def hash_calc_view(request):
    try:
        data = json.loads(request.body)
        text = data.get("text", "")
        algorithm = data.get("algorithm", "md5").lower()

        if not text:
            return JsonResponse({"error": "Text is required"}, status=400)

        supported = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha224": hashlib.sha224,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
        }

        if algorithm not in supported:
            return JsonResponse({
                "error": f"Unsupported algorithm: {algorithm}. Supported: {', '.join(supported.keys())}"
            }, status=400)

        start_time = time.time()
        encoded = text.encode("utf-8")
        hash_obj = supported[algorithm](encoded)
        hash_hex = hash_obj.hexdigest()
        elapsed = round((time.time() - start_time) * 1000, 2)

        if request.user.is_authenticated:
            save_scan_history(
                user=request.user,
                scan_type='HASH',
                target=text[:200],
                verdict='SAFE',
                duration=int(elapsed),
                engine='sandbox-hash-calc',
                metadata={
                    'algorithm': algorithm,
                    'hash': hash_hex,
                    'char_count': len(text),
                },
            )

        return JsonResponse({
            "algorithm": algorithm,
            "hash": hash_hex,
            "char_count": len(text),
            "byte_count": len(encoded),
            "duration_ms": elapsed,
        })

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
