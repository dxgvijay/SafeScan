from django.core.cache import cache


def cached_or_compute(cache_key: str, func, timeout: int = 300):
    result = cache.get(cache_key)
    if result is not None:
        return result
    result = func()
    cache.set(cache_key, result, timeout)
    return result
