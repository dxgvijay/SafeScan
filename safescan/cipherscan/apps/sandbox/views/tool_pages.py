from django.views.generic import TemplateView


class SandboxPortScannerView(TemplateView):
    template_name = "pages/tools/port_scanner.html"


class SandboxHashCalculatorView(TemplateView):
    template_name = "pages/tools/hash_calculator.html"


class SandboxBase64View(TemplateView):
    template_name = "pages/tools/base64.html"


class SandboxRegexView(TemplateView):
    template_name = "pages/tools/regex.html"
