from django.urls import path

from apps.core.views.pages import SandboxEditorView
from apps.sandbox.views.tool_pages import (
    SandboxPortScannerView,
    SandboxHashCalculatorView,
    SandboxBase64View,
    SandboxRegexView,
)

urlpatterns = [
    path("port-scanner/", SandboxPortScannerView.as_view(), name="sandbox_port_scanner"),
    path("hash-calculator/", SandboxHashCalculatorView.as_view(), name="sandbox_hash_calculator"),
    path("base64/", SandboxBase64View.as_view(), name="sandbox_base64"),
    path("regex/", SandboxRegexView.as_view(), name="sandbox_regex"),
    path("code-editor/", SandboxEditorView.as_view(), name="sandbox_code_editor"),
]
