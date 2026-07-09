import os
import sys
sys.path.insert(0, 'C:/Django Project/SafeScan/safescan/cipherscan')
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'
import django; django.setup()

from django.core.management.base import BaseCommand
from apps.accounts.accounts.models import ScanHistory
from apps.accounts.utils.scan_history_helper import save_scan_history
from apps.urlscanner.models import URLScan
from apps.filescanner.models import FileScan
from apps.phishing.phishing.models import EmailHeaderScan, EmailContentScan


def backfill_url_scans():
    count = 0
    for scan in URLScan.objects.filter(status='complete').exclude(user=None):
        target = scan.url
        verdict = 'MALICIOUS' if scan.is_malicious else 'SAFE'
        threat_score = scan.threat_score or 0
        try:
            _, created = ScanHistory.objects.get_or_create(
                user=scan.user,
                scan_type='URL',
                target=target,
                defaults={
                    'verdict': verdict,
                    'threat_score': threat_score,
                    'duration': scan.scan_duration_ms,
                    'engine': 'virustotal',
                    'created_at': scan.scanned_at,
                    'metadata': {
                        'scan_id': scan.id,
                        'vendors_total': scan.vendors_total or 0,
                        'vendors_flagged': scan.vendors_flagged or 0,
                        'threat_type': scan.threat_type or '',
                    },
                },
            )
            if created:
                count += 1
        except Exception:
            pass
    return count


def backfill_file_scans():
    count = 0
    for scan in FileScan.objects.filter(status='complete').exclude(user=None):
        target = scan.file_name
        verdict = 'MALICIOUS' if scan.is_malicious else 'SAFE'
        threat_score = scan.threat_score or 0
        try:
            _, created = ScanHistory.objects.get_or_create(
                user=scan.user,
                scan_type='FILE',
                target=target,
                defaults={
                    'verdict': verdict,
                    'threat_score': threat_score,
                    'duration': scan.scan_duration_ms,
                    'engine': 'virustotal',
                    'created_at': scan.scanned_at,
                    'metadata': {
                        'scan_id': scan.id,
                        'vendors_total': scan.vendors_total or 0,
                        'vendors_flagged': scan.vendors_flagged or 0,
                        'threat_type': scan.threat_type or '',
                        'file_size': scan.file_size or 0,
                    },
                },
            )
            if created:
                count += 1
        except Exception:
            pass
    return count


def backfill_email_scans():
    count = 0
    for scan in EmailHeaderScan.objects.exclude(user=None):
        target = scan.from_email or 'unknown'
        verdict = 'MALICIOUS' if scan.is_malicious else 'SAFE'
        try:
            _, created = ScanHistory.objects.get_or_create(
                user=scan.user,
                scan_type='EMAIL',
                target=target,
                defaults={
                    'verdict': verdict,
                    'threat_score': scan.threat_score or 0,
                    'engine': 'phishing-analyzer',
                    'created_at': scan.scanned_at,
                    'metadata': {
                        'scan_id': scan.id,
                        'model': 'EmailHeaderScan',
                    },
                },
            )
            if created:
                count += 1
        except Exception:
            pass
    return count


class Command(BaseCommand):
    help = 'Backfill existing scan results into ScanHistory'

    def handle(self, *args, **options):
        url_count = backfill_url_scans()
        file_count = backfill_file_scans()
        email_count = backfill_email_scans()
        total = url_count + file_count + email_count
        self.stdout.write(self.style.SUCCESS(
            f'Backfilled {total} scans: {url_count} URL, {file_count} File, {email_count} Email'
        ))
