from datetime import timedelta, datetime
from collections import defaultdict
from django.db.models import Count, Q
from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth import get_user_model

from apps.accounts.accounts.models import ScanHistory

User = get_user_model()

CACHE_TTL = 60


class DashboardStatsService:
    def __init__(self, user=None):
        self.user = user
        self._qs = ScanHistory.objects.filter(user=user) if user else ScanHistory.objects.none()
        self._all_qs = ScanHistory.objects.all()

    def get_total_scans(self):
        cache_key = f'dash_total_scans_u{self.user.id}' if self.user else 'dash_total_scans_anon'
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        val = self._qs.count()
        cache.set(cache_key, val, CACHE_TTL)
        return val

    def get_total_threats(self):
        cache_key = f'dash_total_threats_u{self.user.id}' if self.user else 'dash_total_threats_anon'
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        val = self._qs.filter(verdict='MALICIOUS').count()
        cache.set(cache_key, val, CACHE_TTL)
        return val

    def get_files_scanned(self):
        return self._qs.filter(scan_type='FILE').count()

    def get_urls_scanned(self):
        return self._qs.filter(scan_type='URL').count()

    def get_emails_scanned(self):
        return self._qs.filter(scan_type='EMAIL').count()

    def get_ips_scanned(self):
        return self._qs.filter(scan_type='IP').count()

    def get_hashes(self):
        return self._qs.filter(scan_type='HASH').count()

    def get_ports(self):
        return self._qs.filter(scan_type='PORT').count()

    def get_scan_change_pct(self, scan_type=None):
        now = timezone.now()
        period = timedelta(days=7)
        prev_start = now - 2 * period
        prev_end = now - period
        curr_start = now - period

        base_qs = self._qs
        if scan_type:
            base_qs = base_qs.filter(scan_type=scan_type)

        curr = base_qs.filter(created_at__gte=curr_start).count()
        prev = base_qs.filter(created_at__gte=prev_start, created_at__lt=prev_end).count()

        if prev == 0:
            return '+100' if curr > 0 else '0'
        pct = ((curr - prev) / prev) * 100
        return f'{pct:+.0f}'

    def get_recent_activity(self, limit=20):
        cache_key = f'dash_recent_activity_u{self.user.id}_{limit}' if self.user else f'dash_recent_activity_{limit}'
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        scans = self._qs.order_by('-created_at')[:limit]
        result = []
        for s in scans:
            result.append({
                'type': s.scan_type.lower(),
                'icon': self._icon_for_type(s.scan_type),
                'target': s.target[:100] if s.target else 'N/A',
                'status': 'completed',
                'verdict': s.verdict,
                'threat_score': s.threat_score,
                'date': s.created_at,
                'id': str(s.id),
                'username': self.user.username if self.user else '',
            })
        cache.set(cache_key, result, CACHE_TTL)
        return result

    def get_threat_distribution(self):
        cache_key = f'dash_threat_dist_u{self.user.id}' if self.user else 'dash_threat_dist_anon'
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        total = self._qs.count()
        if total == 0:
            result = {'labels': ['Safe', 'Suspicious', 'Malicious'], 'data': [0, 0, 0], 'total': 0}
            cache.set(cache_key, result, CACHE_TTL)
            return result
        malicious = self._qs.filter(verdict='MALICIOUS').count()
        suspicious = self._qs.filter(verdict='SUSPICIOUS').count()
        safe = self._qs.filter(verdict='SAFE').count()
        labels = ['Safe', 'Suspicious', 'Malicious']
        data = [safe, suspicious, malicious]
        result = {'labels': labels, 'data': data, 'total': total}
        cache.set(cache_key, result, CACHE_TTL)
        return result

    def get_scan_history(self, days=30):
        cache_key = f'dash_scan_history_u{self.user.id}_{days}' if self.user else f'dash_scan_history_{days}'
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        now = timezone.now()
        start = now - timedelta(days=days)
        scans = self._qs.filter(created_at__gte=start).order_by('created_at')
        daily = defaultdict(int)
        for s in scans:
            day_key = s.created_at.strftime('%Y-%m-%d')
            daily[day_key] += 1
        data = []
        for i in range(days):
            day = (start + timedelta(days=i + 1)).strftime('%Y-%m-%d')
            data.append(daily.get(day, 0))
        result = {'data': data, 'total': sum(data)}
        cache.set(cache_key, result, CACHE_TTL)
        return result

    def get_user_statistics(self):
        scans = self.get_total_scans()
        api_count = 0
        if self.user:
            try:
                from apps.accounts.models import ApiToken
                api_count = ApiToken.objects.filter(user=self.user).count()
            except Exception:
                api_count = 0
        return {
            'user_scans': scans,
            'api_calls': api_count or 0,
            'reports_exported': 0,
        }

    def get_quick_scans(self, limit=10):
        if not self.user:
            return []
        scans = self._qs.order_by('-created_at')[:limit]
        result = []
        for s in scans:
            result.append({
                'type': s.scan_type.lower(),
                'target': s.target[:100] if s.target else 'N/A',
                'date': s.created_at,
                'verdict': s.verdict,
                'threat_score': s.threat_score,
                'id': str(s.id),
            })
        return result

    def get_notification_count(self):
        return 0

    def _icon_for_type(self, scan_type):
        icons = {
            'URL': 'bi-link-45deg',
            'FILE': 'bi-file-earmark',
            'EMAIL': 'bi-envelope',
            'IP': 'bi-diagram-2',
            'HASH': 'bi-hash',
            'PORT': 'bi-plug',
        }
        return icons.get(scan_type, 'bi-search')
