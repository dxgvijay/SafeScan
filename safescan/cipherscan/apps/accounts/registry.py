from django.apps import apps as django_apps
from django.conf import settings


class ScanModelRegistry:
    _registry = {}

    @classmethod
    def register(cls, model_path, scan_type, target_field='target', status_field='status',
                 threat_field=None, threat_condition=None, timestamp_field=None,
                 user_field='user', icon='bi-search'):
        cls._registry[scan_type] = {
            'model_path': model_path,
            'scan_type': scan_type,
            'target_field': target_field,
            'status_field': status_field,
            'threat_field': threat_field,
            'threat_condition': threat_condition,
            'timestamp_field': timestamp_field,
            'user_field': user_field,
            'icon': icon,
        }

    @classmethod
    def get_model(cls, scan_type):
        entry = cls._registry.get(scan_type)
        if not entry:
            return None
        try:
            return django_apps.get_model(entry['model_path'])
        except LookupError:
            return None

    @classmethod
    def get_all_models(cls):
        results = []
        for scan_type, entry in cls._registry.items():
            model = cls.get_model(scan_type)
            if model is not None:
                results.append((scan_type, model, entry))
        return results

    @classmethod
    def get_all_types(cls):
        return list(cls._registry.keys())

    @classmethod
    def get_entry(cls, scan_type):
        return cls._registry.get(scan_type)


ScanModelRegistry.register(
    model_path='urlscanner.URLScan',
    scan_type='url',
    target_field='url',
    threat_field='is_malicious',
    threat_condition={'is_malicious': True},
    timestamp_field='scanned_at',
    icon='bi-link-45deg',
)

ScanModelRegistry.register(
    model_path='filescanner.FileScan',
    scan_type='file',
    target_field='file_name',
    threat_field='is_malicious',
    threat_condition={'is_malicious': True},
    timestamp_field='scanned_at',
    icon='bi-file-earmark',
)

ScanModelRegistry.register(
    model_path='sandbox.SandboxExecution',
    scan_type='sandbox',
    target_field='language',
    status_field='status',
    timestamp_field='executed_at',
    icon='bi-box',
)

ScanModelRegistry.register(
    model_path='browser_isolation.IsolationScan',
    scan_type='browser_isolation',
    target_field='url',
    status_field='status',
    threat_field='risk_level',
    threat_condition={'risk_level__in': ['high', 'critical']},
    timestamp_field='created_at',
    icon='bi-window',
)

ScanModelRegistry.register(
    model_path='darkweb.ScanResult',
    scan_type='darkweb',
    target_field='query',
    threat_field='risk_score',
    threat_condition={'risk_score__gte': 50},
    timestamp_field='scanned_at',
    icon='bi-shield-exclamation',
)

ScanModelRegistry.register(
    model_path='phishing.EmailHeaderScan',
    scan_type='email_header',
    target_field='from_email',
    threat_field='is_malicious',
    threat_condition={'is_malicious': True},
    timestamp_field='scanned_at',
    icon='bi-envelope',
)

ScanModelRegistry.register(
    model_path='phishing.EmailContentScan',
    scan_type='email_content',
    target_field='email_body',
    threat_field='is_phishing',
    threat_condition={'is_phishing': True},
    timestamp_field='scanned_at',
    icon='bi-envelope-open',
)

ScanModelRegistry.register(
    model_path='phishing.SuspiciousEmailReport',
    scan_type='suspicious_email',
    target_field='sender_email',
    threat_field='verdict',
    threat_condition={'verdict': 'phishing'},
    timestamp_field='created_at',
    icon='bi-exclamation-triangle',
)

ScanModelRegistry.register(
    model_path='phishing.DomainHealthScan',
    scan_type='domain_health',
    target_field='domain',
    threat_field='health_score',
    threat_condition={'health_score__lt': 50},
    timestamp_field='scanned_at',
    icon='bi-globe',
)

ScanModelRegistry.register(
    model_path='phishing.EmailHealthCheck',
    scan_type='email_health',
    target_field='domain',
    threat_field='health_score',
    threat_condition={'health_score__lt': 50},
    timestamp_field='created_at',
    icon='bi-shield-check',
)
