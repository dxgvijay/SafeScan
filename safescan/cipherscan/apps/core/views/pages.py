import json

from django.shortcuts import redirect, render
from django.views.generic import TemplateView


def browser_isolation_page(request):
    return render(request, "pages/browser_isolation.html")


LANGUAGES = {
    'python': {'key': 'python', 'name': 'Python 3.10', 'monaco': 'python', 'ext': 'py'},
    'javascript': {'key': 'javascript', 'name': 'JavaScript', 'monaco': 'javascript', 'ext': 'js'},
    'nodejs': {'key': 'nodejs', 'name': 'Node.js 18', 'monaco': 'javascript', 'ext': 'js'},
    'bash': {'key': 'bash', 'name': 'Bash 5.2', 'monaco': 'shell', 'ext': 'sh'},
    'c': {'key': 'c', 'name': 'C (GCC 10)', 'monaco': 'c', 'ext': 'c'},
    'cpp': {'key': 'cpp', 'name': 'C++ (GCC 10)', 'monaco': 'cpp', 'ext': 'cpp'},
    'java': {'key': 'java', 'name': 'Java 15', 'monaco': 'java', 'ext': 'java'},
    'php': {'key': 'php', 'name': 'PHP 8.2', 'monaco': 'php', 'ext': 'php'},
    'ruby': {'key': 'ruby', 'name': 'Ruby 3.0', 'monaco': 'ruby', 'ext': 'rb'},
    'go': {'key': 'go', 'name': 'Go 1.16', 'monaco': 'go', 'ext': 'go'},
    'rust': {'key': 'rust', 'name': 'Rust 1.50', 'monaco': 'rust', 'ext': 'rs'},
    'r': {'key': 'r', 'name': 'R 4.1', 'monaco': 'r', 'ext': 'r'},
}


class FeaturesView(TemplateView):
    template_name = "pages/features.html"


class PricingView(TemplateView):
    template_name = "pages/pricing.html"


class AboutView(TemplateView):
    template_name = "pages/about.html"


class ContactView(TemplateView):
    template_name = "pages/contact.html"


class FAQView(TemplateView):
    template_name = "pages/faq.html"


class PrivacyView(TemplateView):
    template_name = "pages/privacy.html"


class TermsView(TemplateView):
    template_name = "pages/terms.html"


class UrlScanView(TemplateView):
    template_name = "pages/url_scan.html"


class FileScanView(TemplateView):
    template_name = "pages/file_scan.html"


def email_scan_redirect(request):
    return redirect("phishing_analysis")


class IPScanView(TemplateView):
    template_name = "pages/ip_scan.html"


class DomainScanView(TemplateView):
    template_name = "pages/domain_scan.html"


class PhishingAnalysisView(TemplateView):
    template_name = "pages/phishing.html"


class EmailHeaderAnalyzerView(TemplateView):
    template_name = "phishing/email_header_analyzer.html"


class EmailHealthCheckerView(TemplateView):
    template_name = "phishing/email_health_checker.html"


class SuspiciousEmailBlockerView(TemplateView):
    template_name = "phishing/suspicious_email_blocker.html"


class BrowserIsolationView(TemplateView):
    template_name = "pages/browser_isolation.html"


class SandboxView(TemplateView):
    template_name = "pages/sandbox.html"


class SandboxEditorView(TemplateView):
    template_name = "pages/sandbox_editor.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        language = kwargs.get("language", "python")
        if language not in LANGUAGES:
            language = "python"
        context["default_language"] = language
        context["languages"] = list(LANGUAGES.values())
        context["languages_json"] = json.dumps(LANGUAGES)
        return context


class ThreatIntelView(TemplateView):
    template_name = "pages/threat_intel.html"


class VulnScanView(TemplateView):
    template_name = "pages/vuln_scan.html"


class SSLCheckerView(TemplateView):
    template_name = "pages/ssl_checker.html"


class DNSLookupView(TemplateView):
    template_name = "pages/dns_lookup.html"


class WHOISLookupView(TemplateView):
    template_name = "pages/whois_lookup.html"


class DarkWebView(TemplateView):
    template_name = "pages/dark_web.html"


class BreachCheckView(TemplateView):
    template_name = "pages/breach_check.html"


class ScanHistoryView(TemplateView):
    template_name = "pages/scan_history.html"


class SavedReportsView(TemplateView):
    template_name = "pages/saved_reports.html"


class SettingsView(TemplateView):
    template_name = "pages/settings.html"


class ApiSettingsView(TemplateView):
    template_name = "pages/api_settings.html"


class ApiDocsView(TemplateView):
    template_name = "pages/api_docs.html"


class HelpView(TemplateView):
    template_name = "pages/help.html"


class DocsView(TemplateView):
    template_name = "pages/docs.html"


class BlogView(TemplateView):
    template_name = "pages/blog.html"


class HashCalculatorView(TemplateView):
    template_name = "pages/hash_calculator.html"


class Base64View(TemplateView):
    template_name = "pages/base64.html"


class RegexTesterView(TemplateView):
    template_name = "pages/regex_tester.html"


class PortScannerView(TemplateView):
    template_name = "pages/port_scanner.html"


class ScanDetailView(TemplateView):
    template_name = "pages/scan_detail.html"
