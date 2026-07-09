import hashlib
import logging
import socket
import time
import traceback
import zlib

import requests
from django.conf import settings
from django.db import models
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response

from apps.accounts.utils.scan_history_helper import save_scan_history
from apps.filescanner.models import FileScan
from apps.filescanner.utils.analysis_engine import run_local_analysis

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 100 * 1024 * 1024
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 30


def _build_local_analysis(file_bytes, file_name, vt_data=None):
    """Run local analysis once and cache on the file_bytes."""
    local = run_local_analysis(file_bytes, file_name, vt_data)
    return local


def _get_confidence_level(threat_score, vendors_total, vendors_flagged):
    if threat_score == 0:
        return "High"
    elif vendors_total > 0 and vendors_flagged / vendors_total < 0.1:
        return "Medium"
    elif threat_score < 50:
        return "Low"
    else:
        return "High"


def _get_risk_category(threat_score):
    if threat_score == 0:
        return "SAFE"
    elif threat_score < 30:
        return "LOW RISK"
    elif threat_score < 60:
        return "MEDIUM RISK"
    elif threat_score < 90:
        return "HIGH RISK"
    else:
        return "CRITICAL"


def _vt_headers():
    api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    return {"x-apikey": api_key, "Accept": "application/json"}


def _error_response(message, scan=None):
    data = {
        "error": message,
        "status": "error",
    }
    if scan:
        data["scan_id"] = scan.id
        data["file_name"] = scan.file_name
        data["file_size"] = scan.file_size
        data["file_hash_md5"] = scan.file_hash_md5
        data["file_hash_sha256"] = scan.file_hash_sha256
    return Response(data, status=200)


def _log_response(resp, step_label):
    logger.info("[FileScanner][%s] Status: %s | URL: %s", step_label, resp.status_code, resp.url)
    logger.info("[FileScanner][%s] Headers: %s", step_label, dict(resp.headers))
    body = resp.text
    if len(body) > 2000:
        logger.info("[FileScanner][%s] Body (truncated): %s ...", step_label, body[:2000])
    else:
        logger.info("[FileScanner][%s] Body: %s", step_label, body)


def _log_exception(exc, step_label, url):
    logger.error("[FileScanner][%s] Exception type: %s | URL: %s", step_label, type(exc).__name__, url)
    logger.error("[FileScanner][%s] Exception message: %s", step_label, str(exc))
    logger.error("[FileScanner][%s] Traceback:\n%s", step_label, traceback.format_exc())
    exc_name = type(exc).__name__
    if "NameResolution" in exc_name:
        logger.error("[FileScanner][%s] DNS resolution failed.", step_label)
    elif "SSLError" in exc_name or "ssl" in str(exc).lower():
        logger.error("[FileScanner][%s] SSL connection failed.", step_label)
    elif "gaierror" in exc_name:
        logger.error("[FileScanner][%s] DNS resolution failed.", step_label)
    elif "ConnectionError" in exc_name or "ConnectionReset" in exc_name or "ConnectionAborted" in exc_name or "ConnectionRefused" in exc_name:
        logger.error("[FileScanner][%s] Connection refused or reset.", step_label)


def _vt_req(method, url, step_label, headers=None, **kwargs):
    logger.info("[FileScanner][%s] Request URL: %s", step_label, url)
    try:
        resp = requests.request(method, url, headers=headers, timeout=VT_TIMEOUT, **kwargs)
        _log_response(resp, step_label)
        return resp
    except requests.ConnectionError as e:
        _log_exception(e, step_label, url)
        raise
    except requests.Timeout as e:
        _log_exception(e, step_label, url)
        raise
    except requests.RequestException as e:
        _log_exception(e, step_label, url)
        raise
    except socket.gaierror as e:
        _log_exception(e, step_label, url)
        raise
    except Exception as e:
        _log_exception(e, step_label, url)
        raise


def _handle_vt_response(resp, step_label):
    if resp.status_code == 200:
        return None
    _log_response(resp, step_label)
    if resp.status_code == 401:
        logger.error("[FileScanner][%s] Invalid VirusTotal API key.", step_label)
        return "Invalid VirusTotal API Key."
    if resp.status_code == 404:
        logger.info("[FileScanner][%s] Hash not found in VirusTotal.", step_label)
        return None
    if resp.status_code == 429:
        logger.error("[FileScanner][%s] VirusTotal quota exceeded.", step_label)
        return "VirusTotal API quota exceeded."
    logger.error("[FileScanner][%s] Unexpected response: status=%s", step_label, resp.status_code)
    return "Unexpected error while contacting VirusTotal."


def _try_fetch_file_attrs(sha256, headers, dest):
    try:
        resp = _vt_req("GET", f"{VT_API_BASE}/files/{sha256}", "fetch_meta", headers=headers)
        if resp.status_code == 200:
            meta = resp.json().get("data", {}).get("attributes", {})
            dest["type_description"] = meta.get("type_description")
            dest["type_tags"] = meta.get("type_tags", [])
            dest["sha1"] = meta.get("sha1")
            dest["first_submission_date"] = meta.get("first_submission_date")
            dest["last_analysis_date"] = meta.get("last_analysis_date")
            dest["times_submitted"] = meta.get("times_submitted")
            dest["type_extension"] = meta.get("type_extension")
            dest["magic"] = meta.get("magic")
            dest["mime_type"] = meta.get("mime_type")
            dest["tags"] = meta.get("tags", [])
            dest["names"] = meta.get("names", [])
            dest["vhash"] = meta.get("vhash")
            dest["authentihash"] = meta.get("authentihash")
            dest["signature_info"] = meta.get("signature_info", {})
            dest["popular_threat_classification"] = meta.get("popular_threat_classification", {})
            dest["crowdsourced_yara_results"] = meta.get("crowdsourced_yara_results", [])
            dest["sandbox_verdicts"] = meta.get("sandbox_verdicts", {})
            dest["pe_info"] = meta.get("pe_info", {})
            dest["trid"] = meta.get("trid", [])
            dest["bundle_info"] = meta.get("bundle_info", {})
            dest["submission_names"] = meta.get("submission_names", [])
    except Exception:
        logger.warning("[FileScanner] Could not fetch file metadata for %s", sha256, exc_info=True)


@api_view(["POST"])
def file_scan_view(request):
    api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    if not api_key or api_key in ("your_api_key_here", "YOUR_VIRUSTOTAL_API_KEY"):
        logger.error("[FileScanner] VirusTotal API key not configured.")
        return _error_response("VirusTotal API key is not configured.")

    if "file" not in request.FILES:
        return _error_response("No file provided")

    uploaded = request.FILES["file"]
    if uploaded.size == 0:
        return _error_response("File is empty")

    if uploaded.size > MAX_FILE_SIZE:
        return _error_response("File exceeds 100MB limit")

    file_bytes = uploaded.read()
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    sha512 = hashlib.sha512(file_bytes).hexdigest()
    sha3_256 = hashlib.sha3_256(file_bytes).hexdigest()
    crc32 = format(zlib.crc32(file_bytes) & 0xFFFFFFFF, '08x')
    file_name = uploaded.name
    file_size = uploaded.size

    # Run local analysis (entropy, strings, doc, archive, PE, findings, risk)
    local_analysis = run_local_analysis(file_bytes, file_name, None)

    logger.info("[FileScanner] Starting scan: name=%s, size=%d, sha256=%s", file_name, file_size, sha256)

    scan = FileScan.objects.create(
        user=request.user if request.user.is_authenticated else None,
        file_name=file_name,
        file_size=file_size,
        file_hash_md5=md5,
        file_hash_sha256=sha256,
        status="scanning",
    )

    headers = _vt_headers()
    start_time = time.monotonic()
    poll_url = None
    file_attrs = {}

    try:
        try:
            lookup_resp = _vt_req("GET", f"{VT_API_BASE}/files/{sha256}", "hash_lookup", headers=headers)
        except (requests.ConnectionError, socket.gaierror) as e:
            _log_exception(e, "hash_lookup", f"{VT_API_BASE}/files/{sha256}")
            scan.status = "error"
            scan.save(update_fields=["status"])
            return _error_response("Unable to connect to VirusTotal.", scan)
        except requests.Timeout as e:
            _log_exception(e, "hash_lookup", f"{VT_API_BASE}/files/{sha256}")
            scan.status = "error"
            scan.save(update_fields=["status"])
            return _error_response("VirusTotal request timed out.", scan)
        except requests.RequestException as e:
            _log_exception(e, "hash_lookup", f"{VT_API_BASE}/files/{sha256}")
            scan.status = "error"
            scan.save(update_fields=["status"])
            return _error_response("Unable to connect to VirusTotal.", scan)

        if lookup_resp.status_code == 401:
            logger.error("[FileScanner][hash_lookup] Invalid VirusTotal API key.")
            scan.status = "error"
            scan.save(update_fields=["status"])
            return _error_response("Invalid VirusTotal API Key.", scan)

        if lookup_resp.status_code == 429:
            logger.error("[FileScanner][hash_lookup] VirusTotal quota exceeded.")
            scan.status = "error"
            scan.save(update_fields=["status"])
            return _error_response("VirusTotal API quota exceeded.", scan)

        if lookup_resp.status_code == 200:
            vt_data = lookup_resp.json()
            raw_attrs = vt_data.get("data", {}).get("attributes", {})
            file_attrs = {
                "meaningful_name": raw_attrs.get("meaningful_name"),
                "type_description": raw_attrs.get("type_description"),
                "type_tags": raw_attrs.get("type_tags", []),
                "md5": raw_attrs.get("md5"),
                "sha1": raw_attrs.get("sha1"),
                "sha256": raw_attrs.get("sha256"),
                "size": raw_attrs.get("size"),
                "last_analysis_date": raw_attrs.get("last_analysis_date"),
                "first_submission_date": raw_attrs.get("first_submission_date"),
                "times_submitted": raw_attrs.get("times_submitted"),
                "type_extension": raw_attrs.get("type_extension"),
                "magic": raw_attrs.get("magic"),
                "mime_type": raw_attrs.get("mime_type"),
                "tags": raw_attrs.get("tags", []),
                "names": raw_attrs.get("names", []),
                "vhash": raw_attrs.get("vhash"),
                "authentihash": raw_attrs.get("authentihash"),
                "signature_info": raw_attrs.get("signature_info", {}),
                "popular_threat_classification": raw_attrs.get("popular_threat_classification", {}),
                "crowdsourced_yara_results": raw_attrs.get("crowdsourced_yara_results", []),
                "sandbox_verdicts": raw_attrs.get("sandbox_verdicts", {}),
                "pe_info": raw_attrs.get("pe_info", {}),
                "trid": raw_attrs.get("trid", []),
                "bundle_info": raw_attrs.get("bundle_info", {}),
                "submission_names": raw_attrs.get("submission_names", []),
            }
            analysis_id = vt_data.get("data", {}).get("id")
            if not analysis_id:
                logger.error("[FileScanner][hash_lookup] No analysis ID in VT response.")
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("No analysis available.", scan)
            poll_url = f"{VT_API_BASE}/analyses/{analysis_id}"
            logger.info("[FileScanner][hash_lookup] Existing analysis found: %s", analysis_id)

        if not poll_url:
            logger.info("[FileScanner] Hash not on VT — uploading file.")
            try:
                upload_resp = _vt_req(
                    "POST", f"{VT_API_BASE}/files", "upload",
                    headers=headers, files={"file": (file_name, file_bytes)},
                )
            except (requests.ConnectionError, socket.gaierror) as e:
                _log_exception(e, "upload", f"{VT_API_BASE}/files")
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("Unable to connect to VirusTotal.", scan)
            except requests.Timeout as e:
                _log_exception(e, "upload", f"{VT_API_BASE}/files")
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("VirusTotal request timed out.", scan)
            except requests.RequestException as e:
                _log_exception(e, "upload", f"{VT_API_BASE}/files")
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("Unable to connect to VirusTotal.", scan)

            if upload_resp.status_code == 401:
                logger.error("[FileScanner][upload] Invalid VirusTotal API key.")
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("Invalid VirusTotal API Key.", scan)

            if upload_resp.status_code == 429:
                logger.error("[FileScanner][upload] VirusTotal quota exceeded.")
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("VirusTotal API quota exceeded.", scan)

            if upload_resp.status_code != 200:
                logger.error("[FileScanner][upload] Upload failed: status=%s", upload_resp.status_code)
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("Unexpected error while contacting VirusTotal.", scan)

            vt_data = upload_resp.json()
            analysis_id = vt_data.get("data", {}).get("id")
            if not analysis_id:
                logger.error("[FileScanner][upload] No analysis ID in upload response.")
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("No analysis available.", scan)

            poll_url = f"{VT_API_BASE}/analyses/{analysis_id}"
            logger.info("[FileScanner][upload] Upload OK, analysis_id=%s", analysis_id)

        poll_data = None
        for attempt in range(30):
            time.sleep(3)
            try:
                poll_resp = _vt_req("GET", poll_url, f"poll_{attempt+1}", headers=headers)
            except (requests.ConnectionError, socket.gaierror) as e:
                _log_exception(e, f"poll_{attempt+1}", poll_url)
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("Unable to connect to VirusTotal.", scan)
            except requests.Timeout as e:
                _log_exception(e, f"poll_{attempt+1}", poll_url)
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("VirusTotal request timed out.", scan)
            except requests.RequestException as e:
                _log_exception(e, f"poll_{attempt+1}", poll_url)
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response("Unable to connect to VirusTotal.", scan)

            poll_err = _handle_vt_response(poll_resp, f"poll_{attempt+1}")
            if poll_err:
                scan.status = "error"
                scan.save(update_fields=["status"])
                return _error_response(poll_err, scan)

            poll_data = poll_resp.json()
            status = poll_data.get("data", {}).get("attributes", {}).get("status")
            logger.info("[FileScanner][poll_%d] status=%s", attempt + 1, status)
            if status == "completed":
                if not file_attrs:
                    _try_fetch_file_attrs(sha256, headers, file_attrs)
                poll_attrs = poll_data.get("data", {}).get("attributes", {})
                poll_stats = poll_attrs.get("stats", {})
                vt_meta = {
                    'vendors_total': sum(poll_stats.get(k, 0) for k in
                        ('harmless', 'malicious', 'suspicious', 'undetected', 'timeout')),
                    'vendors_flagged': poll_stats.get('malicious', 0) + poll_stats.get('suspicious', 0),
                    'signature_info': file_attrs.get('signature_info', {}),
                    'crowdsourced_yara_results': file_attrs.get('crowdsourced_yara_results', []),
                    'popular_threat_classification': file_attrs.get('popular_threat_classification', {}),
                    'pe_info': file_attrs.get('pe_info', {}),
                    'magic': file_attrs.get('magic'),
                }
                local_analysis = _build_local_analysis(file_bytes, file_name, vt_meta)
                break
        else:
            vt_status = poll_data.get("data", {}).get("attributes", {}).get("status") if poll_data else "unknown"
            logger.warning("[FileScanner] Analysis timeout for %s (status=%s)", file_name, vt_status)
            attributes = poll_data.get("data", {}).get("attributes", {}) if poll_data else {}
            stats = attributes.get("stats", {})
            vendors_total = sum(
                stats.get(k, 0)
                for k in ("harmless", "malicious", "suspicious", "undetected", "timeout")
            )
            vendors_flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
            threat_score = round((vendors_flagged / vendors_total) * 100) if vendors_total > 0 else 0

            scan.status = "timeout"
            scan.vendors_total = vendors_total
            scan.vendors_flagged = vendors_flagged
            scan.threat_score = threat_score
            scan.raw_result = poll_data
            scan.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
            scan.save()

            if not file_attrs:
                _try_fetch_file_attrs(sha256, headers, file_attrs)

            # Re-run local analysis with VT data if available
            local_analysis = _build_local_analysis(file_bytes, file_name, file_attrs if file_attrs else None)

            logger.info("[FileScanner] Returning timeout result for %s", file_name)
            return Response({
                "scan_id": scan.id,
                "file_name": file_name,
                "file_size": file_size,
                "file_hash_sha512": sha512,
                "file_hash_crc32": crc32,
                "file_hash_sha256": sha256,
                "file_hash_md5": md5,
                "file_hash_sha3_256": sha3_256,
                "is_malicious": vendors_flagged > 0,
                "threat_type": "Pending",
                "threat_score": threat_score,
                "vendors_total": vendors_total,
                "vendors_flagged": vendors_flagged,
                "raw_result": poll_data,
                "status": "timeout",
                "message": "Analysis is taking longer than expected. Try again later.",
                "file_type_description": file_attrs.get("type_description"),
                "file_type_tags": file_attrs.get("type_tags", []),
                "file_tags": file_attrs.get("tags", []),
                "file_sha1": file_attrs.get("sha1"),
                "file_vhash": file_attrs.get("vhash"),
                "file_authentihash": file_attrs.get("authentihash"),
                "file_first_submission_date": file_attrs.get("first_submission_date"),
                "file_last_analysis_date": file_attrs.get("last_analysis_date"),
                "file_times_submitted": file_attrs.get("times_submitted"),
                "stats_detail": stats,
                "detection_ratio": f"{vendors_flagged}/{vendors_total}",
                "vt_scan_id": poll_url.split("/")[-1] if poll_url else None,
                "scan_duration_ms": scan.scan_duration_ms,
                "file_extension": file_attrs.get("type_extension") or (file_name.rsplit('.', 1)[-1] if '.' in file_name else None),
                "mime_type": file_attrs.get("mime_type") or file_attrs.get("magic"),
                "magic_byte": file_attrs.get("magic"),
                "confidence_level": _get_confidence_level(threat_score, vendors_total, vendors_flagged),
                "risk_category": _get_risk_category(threat_score),
                "vt_api_version": "v3",
                "api_status": "Operational",
                "rate_limit_status": "Available",
                "last_analysis_date": file_attrs.get("last_analysis_date"),
                "signature_info": file_attrs.get("signature_info", {}),
                "popular_threat_classification": file_attrs.get("popular_threat_classification", {}),
                "crowdsourced_yara_results": file_attrs.get("crowdsourced_yara_results", []),
                "sandbox_verdicts": file_attrs.get("sandbox_verdicts", {}),
                "pe_info": file_attrs.get("pe_info", {}),
                "trid": file_attrs.get("trid", []),
                "known_names": file_attrs.get("names", []),
                "submission_names": file_attrs.get("submission_names", []),
                "bundle_info": file_attrs.get("bundle_info", {}),
                "local_analysis": local_analysis,
            }, status=200)

        attributes = poll_data["data"]["attributes"]
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})

        vendors_total = sum(
            stats.get(k, 0)
            for k in ("harmless", "malicious", "suspicious", "undetected", "timeout")
        )
        vendors_flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
        is_malicious = vendors_flagged > 0
        threat_score = round((vendors_flagged / vendors_total) * 100) if vendors_total > 0 else 0

        if stats.get("malicious", 0) > 0:
            threat_type = "Malware"
        elif stats.get("suspicious", 0) > 0:
            threat_type = "Suspicious"
        else:
            threat_type = "Clean"

        scan.status = "complete"
        scan.is_malicious = is_malicious
        scan.threat_type = threat_type
        scan.threat_score = threat_score
        scan.vendors_total = vendors_total
        scan.vendors_flagged = vendors_flagged
        scan.raw_result = poll_data
        scan.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
        scan.save()

        save_scan_history(
            user=request.user,
            scan_type='FILE',
            target=file_name,
            verdict='MALICIOUS' if is_malicious else 'SAFE',
            threat_score=threat_score,
            duration=scan.scan_duration_ms,
            engine='virustotal',
            metadata={
                'scan_id': scan.id,
                'vendors_total': vendors_total,
                'vendors_flagged': vendors_flagged,
                'threat_type': threat_type,
                'file_size': file_size,
                'sha256': sha256,
            },
        )

        logger.info("[FileScanner] Complete for %s: malicious=%d, total=%d, score=%d",
                     file_name, vendors_flagged, vendors_total, threat_score)

        if threat_score >= 90:
            threat_level_label = "Critical"
        elif threat_score >= 60:
            threat_level_label = "High Risk"
        elif threat_score >= 30:
            threat_level_label = "Medium Risk"
        elif threat_score > 0:
            threat_level_label = "Low Risk"
        else:
            threat_level_label = "Clean"

        detection_ratio = f"{vendors_flagged}/{vendors_total}"
        vt_scan_id = poll_data.get("data", {}).get("id")

        return Response({
            "scan_id": scan.id,
            "file_name": file_name,
            "file_size": file_size,
            "file_hash_sha512": sha512,
            "file_hash_crc32": crc32,
            "file_hash_sha256": sha256,
            "file_hash_md5": md5,
            "file_hash_sha3_256": sha3_256,
            "is_malicious": is_malicious,
            "threat_type": threat_type,
            "threat_level_label": threat_level_label,
            "threat_score": threat_score,
            "vendors_total": vendors_total,
            "vendors_flagged": vendors_flagged,
            "raw_result": results,
            "status": "complete",
            "file_type_description": file_attrs.get("type_description"),
            "file_type_tags": file_attrs.get("type_tags", []),
            "file_tags": file_attrs.get("tags", []),
            "file_sha1": file_attrs.get("sha1"),
            "file_vhash": file_attrs.get("vhash"),
            "file_authentihash": file_attrs.get("authentihash"),
            "stats_detail": stats,
            "detection_ratio": detection_ratio,
            "vt_scan_id": vt_scan_id,
            "scan_duration_ms": scan.scan_duration_ms,
            "scan_date": attributes.get("date") or file_attrs.get("last_analysis_date"),
            "first_submission_date": file_attrs.get("first_submission_date"),
            "times_submitted": file_attrs.get("times_submitted"),
            "file_extension": file_attrs.get("type_extension") or (file_name.rsplit('.', 1)[-1] if '.' in file_name else None),
            "mime_type": file_attrs.get("mime_type") or file_attrs.get("magic"),
            "magic_byte": file_attrs.get("magic"),
            "confidence_level": _get_confidence_level(threat_score, vendors_total, vendors_flagged),
            "risk_category": _get_risk_category(threat_score),
            "vt_api_version": "v3",
            "api_status": "Operational",
            "rate_limit_status": "Available",
            "last_analysis_date": file_attrs.get("last_analysis_date"),
            "signature_info": file_attrs.get("signature_info", {}),
            "popular_threat_classification": file_attrs.get("popular_threat_classification", {}),
            "crowdsourced_yara_results": file_attrs.get("crowdsourced_yara_results", []),
            "sandbox_verdicts": file_attrs.get("sandbox_verdicts", {}),
            "pe_info": file_attrs.get("pe_info", {}),
            "trid": file_attrs.get("trid", []),
            "known_names": file_attrs.get("names", []),
            "submission_names": file_attrs.get("submission_names", []),
            "bundle_info": file_attrs.get("bundle_info", {}),
            "local_analysis": local_analysis,
        }, status=200)

    except Exception as e:
        _log_exception(e, "unhandled", f"{VT_API_BASE}/files/{sha256}")
        scan.status = "error"
        scan.raw_result = {"error": str(e)}
        scan.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
        scan.save(update_fields=["status", "raw_result", "scan_duration_ms"])
        return _error_response("Unexpected error while contacting VirusTotal.", scan)


def file_recent_view(request):
    scans = FileScan.objects.filter(
        status="complete"
    ).order_by("-scanned_at")[:20]

    data = []
    for scan in scans:
        data.append({
            "file_name": scan.file_name,
            "file_type": scan.file_type or "Unknown",
            "vendors_flagged": scan.vendors_flagged,
            "vendors_total": scan.vendors_total,
            "is_malicious": scan.is_malicious,
            "threat_type": scan.threat_type or "Clean",
            "threat_score": scan.threat_score or 0,
            "scanned_at": scan.scanned_at.strftime("%d %b %Y, %H:%M"),
            "file_hash_md5": scan.file_hash_md5 or "",
            "file_hash_sha256": scan.file_hash_sha256 or "",
        })

    return JsonResponse({"scans": data})


def file_search_view(request):
    hash_value = request.GET.get("hash", "").strip().lower()

    if not hash_value:
        return JsonResponse({"error": "Hash value required"}, status=400)

    try:
        scan = FileScan.objects.filter(
            status="complete"
        ).filter(
            models.Q(file_hash_md5=hash_value) |
            models.Q(file_hash_sha256=hash_value)
        ).order_by("-scanned_at").first()

        if not scan:
            return JsonResponse({
                "error": "No report found for this hash",
                "found": False,
            }, status=404)

        # Extract VT data from stored raw_result (which is the full poll_data)
        poll_data = scan.raw_result
        stats = {}
        results = {}
        scan_date = None
        if isinstance(poll_data, dict) and "data" in poll_data:
            attrs = poll_data.get("data", {}).get("attributes", {})
            stats = attrs.get("stats", {})
            results = attrs.get("results", {})
            scan_date = attrs.get("date")

        vendors_total = scan.vendors_total or sum(
            stats.get(k, 0) for k in ("harmless", "malicious", "suspicious", "undetected", "timeout")
        )
        vendors_flagged = scan.vendors_flagged or (stats.get("malicious", 0) + stats.get("suspicious", 0))
        threat_score = scan.threat_score or (round((vendors_flagged / vendors_total) * 100) if vendors_total > 0 else 0)

        threat_level_label = "Clean"
        if threat_score >= 90:
            threat_level_label = "Critical"
        elif threat_score >= 60:
            threat_level_label = "High Risk"
        elif threat_score >= 30:
            threat_level_label = "Medium Risk"
        elif threat_score > 0:
            threat_level_label = "Low Risk"

        return JsonResponse({
            "found": True,
            "scan_id": scan.id,
            "file_name": scan.file_name,
            "file_size": scan.file_size,
            "file_hash_md5": scan.file_hash_md5 or "",
            "file_hash_sha256": scan.file_hash_sha256 or "",
            "is_malicious": scan.is_malicious,
            "threat_type": scan.threat_type or "Clean",
            "threat_score": threat_score,
            "vendors_total": vendors_total,
            "vendors_flagged": vendors_flagged,
            "detection_ratio": f"{vendors_flagged}/{vendors_total}",
            "vt_scan_id": scan.id,
            "scan_duration_ms": scan.scan_duration_ms,
            "scan_date": scan_date,
            "first_submission_date": None,
            "last_analysis_date": scan_date,
            "stats_detail": stats,
            "raw_result": results,
            "confidence_level": _get_confidence_level(threat_score, vendors_total, vendors_flagged),
            "risk_category": _get_risk_category(threat_score),
            "threat_level_label": threat_level_label,
            "file_type_description": None,
            "file_type_tags": [],
            "file_sha1": None,
            "file_extension": scan.file_name.rsplit(".", 1)[-1] if "." in scan.file_name else None,
            "mime_type": None,
            "status": "complete",
            "vt_api_version": "v3",
            "api_status": "Operational",
            "rate_limit_status": "Available",
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
