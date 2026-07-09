import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)
MAX_WORKERS = 6


def run_parallel(checks):
    """
    Execute source check functions concurrently.
    `checks` is a list of (label, callable) tuples.
    Returns a dict of {label: result_dict}.
    Each result dict has at least a "name" key from the source function.
    If a check crashes, returns a structured error result instead of crashing.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(checks))) as pool:
        futures = {}
        for label, fn in checks:
            futures[pool.submit(fn)] = label

        for future in as_completed(futures):
            label = futures[future]
            try:
                result = future.result()
                results[label] = result
            except Exception as e:
                logger.exception("Source check %s failed with exception", label)
                # Derive a display name from label
                display_name = label.replace("_", " ").title()
                results[label] = {
                    "name": display_name,
                    "status": "error",
                    "data": None,
                    "message": "Source Unavailable",
                }
    return results
