import base64
import json
import time
import os
import uuid

from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt


MAX_FILE_SIZE = 100 * 1024 * 1024


def _detect_invalid_base64(text):
    if not text or not text.strip():
        return "Input is empty"
    cleaned = text.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    if len(cleaned) % 4 != 0:
        return "Invalid Base64: length must be a multiple of 4 (check padding)"
    valid_chars = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    )
    for ch in cleaned:
        if ch not in valid_chars:
            return f"Invalid Base64 character: '{ch}'"
    try:
        base64.b64decode(cleaned, validate=True)
    except Exception as e:
        return f"Invalid Base64: {str(e)}"
    return None


@csrf_exempt
@require_http_methods(["POST"])
def base64_process_view(request):
    try:
        content_type = request.content_type or ""
        mode = None
        action = None
        input_text = None
        uploaded_file = None

        if "multipart/form-data" in content_type:
            mode = request.POST.get("mode", "encode")
            action = request.POST.get("action", "text")
            input_text = request.POST.get("text", "")
            uploaded_file = request.FILES.get("file")
        else:
            body = json.loads(request.body)
            mode = body.get("mode", "encode")
            action = body.get("action", "text")
            input_text = body.get("text", "")

        if action == "file":
            if not uploaded_file:
                return JsonResponse({"error": "No file provided"}, status=400)
            if uploaded_file.size > MAX_FILE_SIZE:
                return JsonResponse(
                    {"error": f"File exceeds maximum size of 100 MB."}, status=400
                )

            if mode == "encode":
                data = uploaded_file.read()
                encoded = base64.b64encode(data).decode("ascii")
                result = {
                    "mode": "encode",
                    "action": "file",
                    "result": encoded,
                    "filename": uploaded_file.name + ".b64",
                    "original_filename": uploaded_file.name,
                    "size_display": _format_bytes(len(data)),
                    "byte_count": len(data),
                    "result_bytes": len(encoded),
                    "mime_type": uploaded_file.content_type or "application/octet-stream",
                }
                return JsonResponse(result)
            else:
                try:
                    text_data = uploaded_file.read().decode("utf-8")
                except UnicodeDecodeError:
                    return JsonResponse(
                        {"error": "File must contain UTF-8 text for Base64 decoding"},
                        status=400,
                    )
                cleaned = text_data.strip().replace(" ", "").replace("\n", "").replace("\r", "")
                err = _detect_invalid_base64(cleaned)
                if err:
                    return JsonResponse({"error": err, "position": _find_error_pos(cleaned)}, status=400)
                try:
                    decoded = base64.b64decode(cleaned)
                except Exception as e:
                    pos = _find_error_pos(cleaned)
                    return JsonResponse(
                        {"error": f"Invalid Base64: {str(e)}", "position": pos},
                        status=400,
                    )
                orig_name = uploaded_file.name
                if orig_name.lower().endswith(".b64"):
                    orig_name = orig_name[:-4]
                result = {
                    "mode": "decode",
                    "action": "file",
                    "result": _to_hex_if_binary(decoded),
                    "is_binary": _is_binary(decoded),
                    "binary_data_available": True,
                    "filename": orig_name + ".decoded",
                    "original_filename": orig_name,
                    "size_display": _format_bytes(len(decoded)),
                    "byte_count": len(decoded),
                    "result_bytes": len(decoded),
                    "mime_type": _guess_mime(orig_name),
                }
                return JsonResponse(result)

        if action == "text":
            if mode == "encode":
                if not input_text:
                    return JsonResponse({"error": "No text provided"}, status=400)
                encoded = base64.b64encode(input_text.encode("utf-8")).decode("ascii")
                result = {
                    "mode": "encode",
                    "action": "text",
                    "result": encoded,
                    "char_count": len(input_text),
                    "byte_count": len(input_text.encode("utf-8")),
                    "result_bytes": len(encoded),
                    "duration_ms": 0,
                }
                return JsonResponse(result)
            else:
                if not input_text:
                    return JsonResponse({"error": "No Base64 text provided"}, status=400)
                cleaned = input_text.strip().replace(" ", "").replace("\n", "").replace("\r", "")
                err = _detect_invalid_base64(cleaned)
                if err:
                    pos = _find_error_pos(cleaned)
                    return JsonResponse({"error": err, "position": pos}, status=400)
                try:
                    decoded = base64.b64decode(cleaned)
                except Exception as e:
                    pos = _find_error_pos(cleaned)
                    return JsonResponse(
                        {"error": f"Invalid Base64: {str(e)}", "position": pos},
                        status=400,
                    )
                try:
                    decoded_text = decoded.decode("utf-8")
                    is_binary = False
                except (UnicodeDecodeError, UnicodeError):
                    decoded_text = _to_hex_if_binary(decoded)
                    is_binary = True

                result = {
                    "mode": "decode",
                    "action": "text",
                    "result": decoded_text,
                    "is_binary": is_binary,
                    "char_count": len(cleaned),
                    "byte_count": len(decoded),
                    "duration_ms": 0,
                }
                return JsonResponse(result)

        return JsonResponse({"error": "Invalid request"}, status=400)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def base64_download_view(request):
    try:
        body = json.loads(request.body)
        data_b64 = body.get("data", "")
        filename = body.get("filename", "decoded.bin")
        is_binary = body.get("is_binary", False)

        if not data_b64:
            return JsonResponse({"error": "No data provided"}, status=400)

        if is_binary:
            decoded = base64.b64decode(data_b64)
            response = HttpResponse(decoded, content_type="application/octet-stream")
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response
        else:
            decoded = base64.b64decode(data_b64).decode("utf-8")
            response = HttpResponse(decoded, content_type="text/plain;charset=utf-8")
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def _find_error_pos(text):
    cleaned = text.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    for i, ch in enumerate(cleaned):
        if ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=":
            return i
    try:
        base64.b64decode(cleaned, validate=True)
    except base64.binascii.Error as e:
        err_str = str(e)
        if "padding" in err_str:
            return len(cleaned)
    return -1


def _is_binary(data):
    try:
        data.decode("utf-8")
        return False
    except (UnicodeDecodeError, UnicodeError):
        return True


def _to_hex_if_binary(data):
    if _is_binary(data):
        return "<binary data: " + _format_bytes(len(data)) + " — use Download to save>"
    return data.decode("utf-8")


def _format_bytes(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def _guess_mime(filename):
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    mime_map = {
        ".txt": "text/plain",
        ".html": "text/html",
        ".htm": "text/html",
        ".css": "text/css",
        ".js": "application/javascript",
        ".json": "application/json",
        ".xml": "application/xml",
        ".csv": "text/csv",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
        ".ico": "image/x-icon",
        ".pdf": "application/pdf",
        ".zip": "application/zip",
        ".gz": "application/gzip",
        ".tar": "application/x-tar",
        ".mp3": "audio/mpeg",
        ".mp4": "video/mp4",
        ".webm": "video/webm",
    }
    return mime_map.get(ext, "application/octet-stream")
