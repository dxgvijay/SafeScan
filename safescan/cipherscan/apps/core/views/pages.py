from django.views.generic import TemplateView


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


class EmailScanView(TemplateView):
    template_name = "pages/email_scan.html"


class IPScanView(TemplateView):
    template_name = "pages/ip_scan.html"


class DomainScanView(TemplateView):
    template_name = "pages/domain_scan.html"


class PhishingAnalysisView(TemplateView):
    template_name = "pages/phishing.html"


class EmailHeaderAnalyzerView(TemplateView):
    template_name = "pages/phishing.html"


class EmailHealthCheckerView(TemplateView):
    template_name = "pages/phishing.html"


class SuspiciousEmailBlockerView(TemplateView):
    template_name = "pages/phishing.html"


class SandboxView(TemplateView):
    template_name = "pages/sandbox.html"


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


class ScanDetailView(TemplateView):
    template_name = "pages/scan_detail.html"
