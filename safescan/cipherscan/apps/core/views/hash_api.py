import hashlib
import json
import time

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

from apps.accounts.utils.scan_history_helper import save_scan_history

ALGORITHM_DESCRIPTIONS = {
    "md5": "128-bit hash. Fast but cryptographically broken. Use only for checksums.",
    "sha1": "160-bit hash. Deprecated for security. Use only for legacy compatibility.",
    "sha224": "224-bit SHA-2 variant. Good balance of speed and security.",
    "sha256": "256-bit SHA-2. Industry standard for integrity and security.",
    "sha384": "384-bit SHA-2. Stronger than SHA-256, used in high-security environments.",
    "sha512": "512-bit SHA-2. Maximum strength. Ideal for cryptographic applications.",
}

ALGORITHM_CLASSES = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

ALGORITHM_BITS = {
    "md5": 128,
    "sha1": 160,
    "sha224": 224,
    "sha256": 256,
    "sha384": 384,
    "sha512": 512,
}


@csrf_exempt
@require_http_methods(["POST"])
def hash_calculate_view(request):
    try:
        data_bytes = None
        input_type = "text"
        filename = None
        content_type = request.content_type or ""

        if "multipart/form-data" in content_type:
            if request.FILES.get("file"):
                uploaded = request.FILES["file"]
                if uploaded.size > 100 * 1024 * 1024:
                    return JsonResponse(
                        {"error": "File exceeds maximum size of 100 MB."}, status=400
                    )
                data_bytes = uploaded.read()
                filename = uploaded.name
                input_type = "file"
            else:
                text = request.POST.get("text", "")
                data_bytes = text.encode("utf-8")
        else:
            try:
                body = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({"error": "Invalid JSON"}, status=400)
            text = body.get("text", "")
            data_bytes = text.encode("utf-8")

        if not data_bytes:
            return JsonResponse({"error": "No input provided"}, status=400)

        input_size = len(data_bytes)
        char_count = len(data_bytes.decode("utf-8", errors="replace"))

        results = []
        total_start = time.time()

        for alg_name in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]:
            alg_start = time.time()
            hash_obj = ALGORITHM_CLASSES[alg_name](data_bytes)
            hash_hex = hash_obj.hexdigest()
            alg_elapsed = round((time.time() - alg_start) * 1000, 2)

            results.append(
                {
                    "algorithm": alg_name,
                    "algorithm_upper": alg_name.upper(),
                    "hash": hash_hex,
                    "bits": ALGORITHM_BITS[alg_name],
                    "char_length": len(hash_hex),
                    "description": ALGORITHM_DESCRIPTIONS[alg_name],
                    "duration_ms": alg_elapsed,
                }
            )

        total_elapsed = round((time.time() - total_start) * 1000, 2)

        if request.user.is_authenticated:
            preview = (text[:200] if input_type == 'text' else filename or 'file')
            save_scan_history(
                user=request.user,
                scan_type='HASH',
                target=preview,
                verdict='SAFE',
                duration=int(total_elapsed),
                engine='hash-calculator',
                metadata={
                    'input_type': input_type,
                    'algorithms': len(results),
                    'input_size': input_size,
                },
            )

        return JsonResponse(
            {
                "input": {
                    "type": input_type,
                    "filename": filename,
                    "char_count": char_count,
                    "byte_count": input_size,
                    "size_display": format_bytes(input_size),
                },
                "algorithms": results,
                "total_duration_ms": total_elapsed,
            }
        )

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def format_bytes(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"
