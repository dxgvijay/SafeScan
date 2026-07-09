from apps.accounts.accounts.models import ScanHistory


def save_scan_history(user, scan_type, target, verdict='SAFE', threat_score=0,
                      duration=None, engine='cipherscan', metadata=None):
    if metadata is None:
        metadata = {}
    if not user or not user.is_authenticated:
        return None
    return ScanHistory.objects.create(
        user=user,
        scan_type=scan_type,
        target=target,
        verdict=verdict,
        threat_score=threat_score,
        duration=duration,
        engine=engine,
        metadata=metadata,
    )
