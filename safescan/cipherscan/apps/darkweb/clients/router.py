import logging

from django.conf import settings

from apps.darkweb.clients.base import DarkWebProvider
from apps.darkweb.clients.hibp import HIBPProvider
from apps.darkweb.clients.mock import MockProvider

logger = logging.getLogger(__name__)

_HIBP_INSTANCE = None
_MOCK_INSTANCE = None


def get_provider() -> DarkWebProvider:
    global _HIBP_INSTANCE, _MOCK_INSTANCE

    api_key = getattr(settings, "HIBP_API_KEY", "")
    if api_key:
        if _HIBP_INSTANCE is None:
            _HIBP_INSTANCE = HIBPProvider(api_key=api_key)
            logger.info("[Router] Using HIBPProvider (API key configured)")
        return _HIBP_INSTANCE

    logger.info("[Router] No HIBP API key — falling back to MockProvider (simulated data)")
    if _MOCK_INSTANCE is None:
        _MOCK_INSTANCE = MockProvider()
    return _MOCK_INSTANCE


def is_breach_check_available() -> bool:
    return True
