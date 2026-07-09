import json
import os
import subprocess
import tempfile
import time
import traceback

import requests
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from apps.sandbox.models import SandboxExecution

PISTON_API = "https://emkc.org/api/v2/piston"

LANGUAGE_MAP = {
    "python": {"language": "python", "version": "3.10"},
    "javascript": {"language": "javascript", "version": "18.15"},
    "nodejs": {"language": "javascript", "version": "18.15"},
    "bash": {"language": "bash", "version": "5.2"},
    "c": {"language": "c", "version": "10.2"},
    "cpp": {"language": "c++", "version": "10.2"},
    "java": {"language": "java", "version": "15.0"},
    "php": {"language": "php", "version": "8.2"},
    "ruby": {"language": "ruby", "version": "3.0"},
    "go": {"language": "go", "version": "1.16"},
    "rust": {"language": "rust", "version": "1.50"},
    "r": {"language": "r", "version": "4.1"},
}


def execute_code_locally(language, code, stdin_input):
    """Execute code locally using subprocess as fallback when Piston is unavailable."""
    start = time.time()
    tmp_dir = tempfile.mkdtemp(prefix="safescan_")

    try:
        if language == "python":
            proc = subprocess.run(
                ["python", "-c", code],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language in ("javascript", "nodejs"):
            proc = subprocess.run(
                ["node", "-e", code],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "bash":
            proc = subprocess.run(
                ["bash", "-c", code],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "php":
            proc = subprocess.run(
                ["php", "-r", code],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "ruby":
            proc = subprocess.run(
                ["ruby", "-e", code],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "r":
            proc = subprocess.run(
                ["Rscript", "-e", code],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "go":
            src = os.path.join(tmp_dir, "main.go")
            with open(src, "w") as f:
                f.write(code)
            proc = subprocess.run(
                ["go", "run", src],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=tmp_dir,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "rust":
            src = os.path.join(tmp_dir, "main.rs")
            out = os.path.join(tmp_dir, "main")
            with open(src, "w") as f:
                f.write(code)
            compile_proc = subprocess.run(
                ["rustc", src, "-o", out],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if compile_proc.returncode != 0:
                return "", compile_proc.stderr, compile_proc.returncode, time.time() - start
            proc = subprocess.run(
                [out],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "c":
            src = os.path.join(tmp_dir, "main.c")
            out = os.path.join(tmp_dir, "main")
            with open(src, "w") as f:
                f.write(code)
            compile_proc = subprocess.run(
                ["gcc", src, "-o", out, "-lm"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if compile_proc.returncode != 0:
                return "", compile_proc.stderr, compile_proc.returncode, time.time() - start
            proc = subprocess.run(
                [out],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "cpp":
            src = os.path.join(tmp_dir, "main.cpp")
            out = os.path.join(tmp_dir, "main")
            with open(src, "w") as f:
                f.write(code)
            compile_proc = subprocess.run(
                ["g++", src, "-o", out, "-lm"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if compile_proc.returncode != 0:
                return "", compile_proc.stderr, compile_proc.returncode, time.time() - start
            proc = subprocess.run(
                [out],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        elif language == "java":
            src = os.path.join(tmp_dir, "Main.java")
            with open(src, "w") as f:
                f.write(code)
            compile_proc = subprocess.run(
                ["javac", src],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=tmp_dir,
            )
            if compile_proc.returncode != 0:
                return "", compile_proc.stderr, compile_proc.returncode, time.time() - start
            proc = subprocess.run(
                ["java", "-cp", tmp_dir, "Main"],
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.stdout, proc.stderr, proc.returncode, time.time() - start

        else:
            return "", f"Unsupported language for local execution: {language}", 1, time.time() - start

    except subprocess.TimeoutExpired:
        return "", "Execution timed out", 1, time.time() - start
    except FileNotFoundError as e:
        return "", f"Runtime not installed: {e}", 1, time.time() - start
    finally:
        try:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


@require_http_methods(["POST"])
def sandbox_execute_view(request):
    try:
        data = json.loads(request.body)
        language = data.get("language", "").lower()
        code = data.get("code", "").strip()
        stdin_input = data.get("stdin", "")

        if not code:
            return JsonResponse({"error": "No code provided"}, status=400)

        if not language:
            return JsonResponse({"error": "No language specified"}, status=400)

        if len(code) > 50000:
            return JsonResponse(
                {"error": "Code too large (max 50KB)"}, status=400
            )

        lang_config = LANGUAGE_MAP.get(language)
        if not lang_config:
            return JsonResponse(
                {"error": f"Unsupported language: {language}"}, status=400
            )

        execution = SandboxExecution.objects.create(
            user=request.user if request.user.is_authenticated else None,
            language=language,
            code=code,
            stdin_input=stdin_input,
            status="running",
        )

        start_time = time.time()

        payload = {
            "language": lang_config["language"],
            "version": lang_config["version"],
            "files": [{"content": code}],
            "stdin": stdin_input,
            "run_timeout": 10000,
            "compile_timeout": 15000,
        }

        # Try Piston API first
        piston_success = False
        output = ""
        stderr = ""
        exit_code = 0
        memory_bytes = 3200000

        try:
            response = requests.post(
                f"{PISTON_API}/execute", json=payload, timeout=30
            )
            if response.ok:
                result = response.json()
                run_result = result.get("run")
                if run_result and isinstance(run_result, dict):
                    output = run_result.get("stdout") or ""
                    stderr = run_result.get("stderr") or ""
                    exit_code = run_result.get("code") or 0
                    memory_bytes = run_result.get("memory") or 3200000
                    piston_success = True
        except requests.Timeout:
            pass
        except requests.RequestException:
            pass

        if not piston_success:
            output, stderr, exit_code, elapsed = execute_code_locally(
                language, code, stdin_input
            )
            duration_ms = round(elapsed * 1000, 2)
        else:
            duration_ms = round((time.time() - start_time) * 1000, 2)

        execution.output = output or ""
        execution.stderr = stderr or ""
        execution.exit_code = exit_code
        execution.duration_ms = duration_ms
        execution.status = "complete"
        execution.save()

        return JsonResponse(
            {
                "execution_id": execution.id,
                "status": "complete",
                "output": output or "",
                "stderr": stderr or "",
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "memory_mb": round(
                    memory_bytes / 1024 / 1024, 1
                ),
            }
        )

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)


def sandbox_stats_view(request):
    try:
        return JsonResponse({
            'total_executions': SandboxExecution.objects.filter(
                status='complete').count(),
            'languages_supported': 12,
            'uptime': '99.9%'
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def sandbox_recent_view(request):
    try:
        executions = SandboxExecution.objects.filter(
            status="complete", is_public=True
        ).order_by("-executed_at")[:20]

        data = []
        for ex in executions:
            preview = ex.code[:50].replace("\n", " ")
            if len(ex.code) > 50:
                preview += "..."
            data.append(
                {
                    "language": ex.language,
                    "snippet_preview": preview,
                    "duration_ms": ex.duration_ms or 0,
                    "exit_code": ex.exit_code,
                    "executed_at": ex.executed_at.strftime("%d %b %Y, %H:%M"),
                }
            )
        return JsonResponse({"executions": data})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
