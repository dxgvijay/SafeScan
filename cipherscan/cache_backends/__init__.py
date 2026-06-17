from django.core.cache.backends.locmem import LocMemCache


class DevCache(LocMemCache):
    pass
