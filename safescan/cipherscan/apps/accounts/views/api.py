from django.db.models import Q
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from apps.accounts.accounts.models import ScanHistory


@api_view(['GET'])
def user_scan_history_api(request):
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

    scans = ScanHistory.objects.filter(user=request.user)

    # ── Filters ────────────────────────────────────────────────────
    scan_type = request.GET.get('type')
    verdict = request.GET.get('verdict')
    search = request.GET.get('search')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')

    if scan_type:
        scans = scans.filter(scan_type=scan_type.upper())
    if verdict:
        scans = scans.filter(verdict=verdict.upper())
    if search:
        scans = scans.filter(
            Q(target__icontains=search) | Q(engine__icontains=search)
        )
    if date_from:
        scans = scans.filter(created_at__gte=date_from)
    if date_to:
        scans = scans.filter(created_at__lte=date_to)

    total_count = scans.count()

    # ── Stats ───────────────────────────────────────────────────────
    stats = {
        'total': total_count,
        'safe': scans.filter(verdict='SAFE').count(),
        'suspicious': scans.filter(verdict='SUSPICIOUS').count(),
        'malicious': scans.filter(verdict='MALICIOUS').count(),
    }

    # ── Pagination ──────────────────────────────────────────────────
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 50))
    offset = (page - 1) * per_page
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    page_scans = scans.order_by('-created_at')[offset:offset + per_page]

    # ── Build response ──────────────────────────────────────────────
    records = []
    for s in page_scans:
        records.append({
            'id': s.id,
            'type': s.scan_type,
            'type_label': s.get_scan_type_display(),
            'target': s.target,
            'verdict': s.verdict,
            'verdict_label': s.get_verdict_display(),
            'threat_score': s.threat_score,
            'status': 'Completed',
            'created_at': s.created_at.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'created_at_display': s.created_at.strftime('%b %d, %H:%M'),
            'duration': s.duration,
            'engine': s.engine,
        })

    return Response({
        'stats': stats,
        'records': records,
        'page': page,
        'per_page': per_page,
        'total_pages': total_pages,
        'total': total_count,
    })
