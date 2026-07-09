import json
import logging
import time

import requests
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from apps.accounts.utils.scan_history_helper import save_scan_history
from apps.filescanner.models import FileScan
from apps.urlscanner.models import URLScan
from apps.urlscanner.serializers.scan import (
    URLScanHistorySerializer,
    URLScanInputSerializer,
    URLScanSerializer,
)

logger = logging.getLogger(__name__)


@api_view(["POST"])
def url_scan_view(request):
    serializer = URLScanInputSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({"success": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    url = serializer.validated_data["url"]
    api_key = settings.VIRUSTOTAL_API_KEY

    if not api_key or api_key in ("your_api_key_here", "YOUR_VIRUSTOTAL_API_KEY"):
        scan = URLScan.objects.create(
            user=request.user if request.user.is_authenticated else None,
            url=url,
            status="error",
        )
        logger.warning("Scan attempted but VIRUSTOTAL_API_KEY is empty or still a placeholder.")
        return Response(
            {
                "success": False,
                "error": "API key not configured. Please add a valid VirusTotal API key.",
                "scan_id": scan.id,
                "status": "error",
            },
            status=status.HTTP_200_OK,
        )

    scan = URLScan.objects.create(
        user=request.user if request.user.is_authenticated else None,
        url=url,
        status="scanning",
    )

    start_time = time.monotonic()

    try:
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

        # STEP 1: POST URL to VirusTotal (form-encoded body, not JSON)
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
        )
        response.raise_for_status()
        response_data = response.json()
        logger.debug("VT POST response: %s", json.dumps(response_data, indent=2))

        analysis_id = response_data["data"]["id"]

        # STEP 2: Poll the analysis endpoint until completed
        poll_data = None
        for _ in range(30):
            time.sleep(3)
            poll_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            poll_resp.raise_for_status()
            poll_data = poll_resp.json()

            logger.debug("VT poll response: %s", json.dumps(poll_data, indent=2))

            if poll_data["data"]["attributes"]["status"] == "completed":
                break
        else:
            # Analysis still not completed after 90 seconds — return partial results
            vt_status = poll_data["data"]["attributes"]["status"] if poll_data else "unknown"
            logger.warning("VT analysis incomplete for %s after 90s (status=%s)", url, vt_status)

            # Save what we have so the user can poll later
            scan.status = "pending"
            scan.raw_result = poll_data
            scan.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
            scan.save(update_fields=["status", "raw_result", "scan_duration_ms"])

            # Parse whatever partial stats are available
            attributes = poll_data["data"]["attributes"] if poll_data else {}
            stats = attributes.get("stats", {})
            vendors_total = (
                stats.get("harmless", 0)
                + stats.get("malicious", 0)
                + stats.get("suspicious", 0)
                + stats.get("undetected", 0)
                + stats.get("timeout", 0)
            )
            vendors_flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
            threat_score = round((vendors_flagged / vendors_total) * 100) if vendors_total > 0 else 0

            scan.vendors_total = vendors_total
            scan.vendors_flagged = vendors_flagged
            scan.threat_score = threat_score
            scan.save(update_fields=["vendors_total", "vendors_flagged", "threat_score"])

            return Response({
                "success": True,
                "scan_id": scan.id,
                "status": "pending",
                "url": scan.url,
                "message": "Scan is taking longer than expected. VirusTotal may be analyzing this URL for the first time. Please try again in 30 seconds.",
                "threat_score": threat_score,
                "vendors_total": vendors_total,
                "vendors_flagged": vendors_flagged,
                "raw_result": poll_data,
            }, status=status.HTTP_200_OK)

        # STEP 3: Parse results from the completed analysis
        attributes = poll_data["data"]["attributes"]
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})

        vendors_total = (
            stats.get("harmless", 0)
            + stats.get("malicious", 0)
            + stats.get("suspicious", 0)
            + stats.get("undetected", 0)
            + stats.get("timeout", 0)
        )
        vendors_flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)

        threat_type = "Clean"
        if stats.get("malicious", 0) > 0:
            threat_type = "Malware"
        elif stats.get("suspicious", 0) > 0:
            threat_type = "Suspicious"

        scan.status = "complete"
        scan.is_malicious = vendors_flagged > 0
        scan.threat_type = threat_type
        scan.threat_score = (
            round((vendors_flagged / vendors_total) * 100) if vendors_total > 0 else 0
        )
        scan.vendors_total = vendors_total
        scan.vendors_flagged = vendors_flagged
        scan.raw_result = poll_data
        scan.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
        scan.save()

        save_scan_history(
            user=request.user,
            scan_type='URL',
            target=url,
            verdict='MALICIOUS' if scan.is_malicious else 'SAFE',
            threat_score=scan.threat_score or 0,
            duration=scan.scan_duration_ms,
            engine='virustotal',
            metadata={
                'scan_id': scan.id,
                'vendors_total': vendors_total,
                'vendors_flagged': vendors_flagged,
                'threat_type': threat_type,
            },
        )

        logger.info(
            "Scan complete for %s — flagged: %d/%d, score: %d",
            url, vendors_flagged, vendors_total, scan.threat_score,
        )

    except requests.RequestException as e:
        scan.status = "error"
        scan.raw_result = {"error": str(e)}
        scan.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
        scan.save(update_fields=["status", "raw_result", "scan_duration_ms"])
        logger.error("VT API request failed for %s: %s", url, str(e))
        return Response(
            {
                "success": False,
                "error": f"VirusTotal API error: {str(e)}",
                "scan_id": scan.id,
                "status": "error",
            },
            status=status.HTTP_200_OK,
        )

    serializer = URLScanSerializer(scan)
    return Response({
        "success": True,
        "scan_id": scan.id,
        "status": scan.status,
        **serializer.data,
    }, status=status.HTTP_200_OK)


@api_view(["GET"])
def url_scan_result_view(request, scan_id):
    try:
        scan = URLScan.objects.get(pk=scan_id)
    except URLScan.DoesNotExist:
        return Response(
            {"error": "Scan not found"},
            status=status.HTTP_404_NOT_FOUND,
        )
    return Response(URLScanSerializer(scan).data)


@api_view(["GET"])
def scan_history_view(request):
    if not request.user.is_authenticated:
        return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

    scans = URLScan.objects.filter(user=request.user).order_by("-scanned_at")[:20]
    serializer = URLScanHistorySerializer(scans, many=True)
    return Response(serializer.data)


@api_view(["GET"])
def recent_scans_view(request):
    scans = URLScan.objects.filter(status="complete").order_by("-scanned_at")[:20]
    serializer = URLScanHistorySerializer(scans, many=True)
    return Response(serializer.data)


@api_view(["GET"])
def stats_view(request):
    urls_scanned = URLScan.objects.filter(status="complete").count()
    files_scanned = FileScan.objects.filter(status="complete").count()
    url_threats = URLScan.objects.filter(is_malicious=True).count()
    file_threats = FileScan.objects.filter(is_malicious=True).count()
    return Response({
        "files_scanned": files_scanned,
        "urls_checked": urls_scanned,
        "urls_scanned": urls_scanned,
        "threats_detected": url_threats + file_threats,
        "malicious_found": url_threats + file_threats,
        "vendors_integrated": 72,
    })
