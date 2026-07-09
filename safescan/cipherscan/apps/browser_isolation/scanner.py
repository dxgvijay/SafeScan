import base64
import json
import logging
import re
import ssl
import socket
import time
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

TIMEOUT = 30000
NAV_TIMEOUT = 25000

SECURITY_HEADER_KEYS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "X-XSS-Protection",
]

TECH_PATTERNS = {
    "React": [r'data-reactroot', r'data-reactid', r'__NEXT_DATA__', r'react\.js', r'react-dom\.js', r'React\.createElement'],
    "Angular": [r'ng-app', r'ng-version', r'angular\.js', r'angular\.min\.js', r'[ng\:]'],
    "Vue": [r'vue\.js', r'vue\.min\.js', r'v-bind', r'v-model', r'v-if', r'v-for', r'__VUE__'],
    "Next.js": [r'__NEXT_DATA__', r'/_next/static', r'next\.js'],
    "Nuxt": [r'__NUXT__', r'/_nuxt/'],
    "WordPress": [r'wp-content', r'wp-includes', r'wp-json', r'wordpress', r'generator.*wordpress'],
    "Drupal": [r'drupal\.js', r'Drupal\.', r'generator.*drupal'],
    "Bootstrap": [r'bootstrap\.css', r'bootstrap\.min\.css', r'bootstrap\.js', r'bootstrap\.min\.js', r'col-[-a-z]+', r'container[-]?'],
    "Tailwind": [r'tailwindcss', r'tailwind\.css', r'class:.*\b(text-\w+-\d+|bg-\w+-\d+|p-\d+|m-\d+)\b'],
    "jQuery": [r'jquery\.js', r'jquery\.min\.js', r'\$\(', r'jQuery\(', r'jquery\/'],
    "Cloudflare": [r'cloudflare', r'cf-ray', r'__cfduid', r'cf-challenge'],
    "Google Analytics": [r'google-analytics\.com', r'ga\.js', r'gtag', r'ga\(', r'__ga'],
    "Google Tag Manager": [r'googletagmanager\.com', r'gtm\.js', r'dataLayer'],
    "Facebook Pixel": [r'facebook\.com\/tr', r'fbq\(', r'connect\.facebook\.net'],
    "Hotjar": [r'hotjar\.com', r'hj\('],
    "Segment": [r'segment\.com', r'analytics\.js', r'segment\.io'],
    "Mixpanel": [r'mixpanel\.com', r'mixpanel\.js'],
}


class BrowserIsolationScanner:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)
        self.base_origin = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

        self.start_time = None
        self.end_time = None

        self.requests_log = []
        self.responses_log = []
        self.redirect_chain_log = []
        self.final_url_value = None
        self.final_status_code = None
        self.final_headers = {}
        self.final_security_details = {}

        self.page_html = ""
        self.sanitized_html = ""
        self.page_metadata = {}
        self.dom_stats = {}
        self.js_analysis = {}
        self.link_analysis = {}
        self.security_headers = {}
        self.cookie_data = []
        self.tech_list = []
        self.tls_info = {}
        self.performance_metrics = {}
        self.resource_summary = {}
        self.screenshot_b64 = None

        self.error_message = None
        self.has_partial = False

    def _ensure_browser(self):
        if self._browser is None:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright()
            self._pw_instance = self._playwright.start()
            self._browser = self._pw_instance.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )

    def _create_context(self):
        self._context = self._browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1366, "height": 768},
            locale="en-US",
            ignore_https_errors=False,
        )

    def _setup_network_listeners(self):
        page = self._page

        def on_request(request):
            self.requests_log.append({
                "url": request.url,
                "method": request.method,
                "type": request.resource_type,
                "headers": dict(request.headers),
                "timestamp": time.monotonic(),
            })

        def on_response(response):
            entry = {
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers),
                "security_details": response.security_details(),
                "timestamp": time.monotonic(),
            }
            self.responses_log.append(entry)

            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                self.redirect_chain_log.append({
                    "url": response.url,
                    "status": response.status,
                    "location": location,
                })

        page.on("request", on_request)
        page.on("response", on_response)

    def _extract_metadata(self):
        try:
            meta = self._page.evaluate("""() => {
                const getMeta = (name) => {
                    const el = document.querySelector('meta[name="' + name + '"]') ||
                                document.querySelector('meta[property="' + name + '"]') ||
                                document.querySelector('meta[http-equiv="' + name + '"]');
                    return el ? el.content : null;
                };
                const getLink = (rel) => {
                    const el = document.querySelector('link[rel="' + rel + '"]');
                    return el ? el.href : null;
                };
                const getOg = (prop) => {
                    const el = document.querySelector('meta[property="og:' + prop + '"]');
                    return el ? el.content : null;
                };
                return {
                    title: document.title || null,
                    meta_description: getMeta('description'),
                    charset: document.characterSet || null,
                    language: document.documentElement.lang || null,
                    canonical_url: getLink('canonical'),
                    generator: getMeta('generator'),
                    viewport: getMeta('viewport'),
                    favicon: getLink('icon') || getLink('shortcut icon') || getLink('apple-touch-icon'),
                    og_title: getOg('title'),
                    og_description: getOg('description'),
                    og_image: getOg('image'),
                    twitter_card: getMeta('twitter:card'),
                    twitter_title: getMeta('twitter:title'),
                    robots: getMeta('robots'),
                };
            }""")
            self.page_metadata = meta
        except Exception as e:
            logger.warning("Metadata extraction failed: %s", e)
            self.page_metadata = {}

    def _extract_dom_stats(self):
        try:
            stats = self._page.evaluate("""() => {
                const all = document.querySelectorAll('*');
                const scripts = document.querySelectorAll('script');
                const metas = document.querySelectorAll('meta');
                const hidden = [...all].filter(el => el.offsetParent === null || el.hidden);
                const resources = performance.getEntriesByType ? performance.getEntriesByType('resource') : [];
                var externalSrcs = [...document.querySelectorAll('script[src]')].map(s => s.src);
                return {
                    total_dom_nodes: all.length,
                    images: document.querySelectorAll('img, picture, source').length,
                    links: document.querySelectorAll('a[href]').length,
                    forms: document.querySelectorAll('form').length,
                    input_fields: document.querySelectorAll('input, textarea, select').length,
                    buttons: document.querySelectorAll('button, input[type="submit"], input[type="button"], input[type="reset"]').length,
                    scripts: scripts.length,
                    inline_scripts: [...scripts].filter(s => !s.src).length,
                    external_scripts: [...scripts].filter(s => s.src).length,
                    external_sources: externalSrcs,
                    css_files: document.querySelectorAll('link[rel="stylesheet"]').length,
                    iframes: document.querySelectorAll('iframe, frame').length,
                    canvas_elements: document.querySelectorAll('canvas').length,
                    video_elements: document.querySelectorAll('video').length,
                    audio_elements: document.querySelectorAll('audio').length,
                    svg_elements: document.querySelectorAll('svg, symbol, use, svg *').length,
                    hidden_elements: hidden.length,
                    meta_tags: metas.length,
                    total_resources: resources.length,
                };
            }""")
            self.dom_stats = stats
        except Exception as e:
            logger.warning("DOM stats extraction failed: %s", e)
            self.dom_stats = {}

    def _extract_js_analysis(self):
        try:
            analysis = self._page.evaluate("""() => {
                const scripts = document.querySelectorAll('script');
                const inlineScripts = [...scripts].filter(s => !s.src);
                const externalScripts = [...scripts].filter(s => s.src);
                const inlineCodes = inlineScripts.map(s => s.textContent || '').join('\\n');
                const allCodes = [...scripts].map(s => s.textContent || '').join('\\n');
                return {
                    inline_javascript: inlineScripts.length > 0,
                    external_javascript: externalScripts.length > 0,
                    eval_usage: (function() { try { return eval.toString().includes('native') && allCodes.includes('eval('); } catch(e) { return false; } })(),
                    document_write: allCodes.includes('document.write(') || allCodes.includes('document.writeln('),
                    setTimeout_string: (allCodes.match(/setTimeout\\s*\\(\\s*['"`]/g) || []).length > 0,
                    setInterval_string: (allCodes.match(/setInterval\\s*\\(\\s*['"`]/g) || []).length > 0,
                    websocket_usage: (function() {
                        try { return typeof WebSocket !== 'undefined' && (allCodes.includes('WebSocket(') || allCodes.includes('new WebSocket')); } catch(e) { return false; }
                    })(),
                    webrtc_usage: (function() {
                        try { return (typeof RTCPeerConnection !== 'undefined' || typeof webkitRTCPeerConnection !== 'undefined') && (allCodes.includes('RTCPeerConnection') || allCodes.includes('createOffer') || allCodes.includes('createDataChannel')); } catch(e) { return false; }
                    })(),
                    clipboard_api: (function() {
                        try { return typeof navigator.clipboard !== 'undefined' && (allCodes.includes('navigator.clipboard') || allCodes.includes('clipboard.write') || allCodes.includes('clipboard.read')); } catch(e) { return false; }
                    })(),
                    notification_api: (function() {
                        try { return typeof Notification !== 'undefined' && (allCodes.includes('Notification(') || allCodes.includes('Notification.requestPermission') || allCodes.includes('new Notification')); } catch(e) { return false; }
                    })(),
                    geolocation_api: (function() {
                        try { return typeof navigator.geolocation !== 'undefined' && (allCodes.includes('geolocation') || allCodes.includes('getCurrentPosition') || allCodes.includes('watchPosition')); } catch(e) { return false; }
                    })(),
                    camera_api: (function() {
                        try { return typeof navigator.mediaDevices !== 'undefined' && (allCodes.includes('getUserMedia') || allCodes.includes('enumerateDevices')); } catch(e) { return false; }
                    })(),
                    microphone_api: (function() {
                        try { return typeof navigator.mediaDevices !== 'undefined' && allCodes.includes('audio') && (allCodes.includes('getUserMedia') || allCodes.includes('enumerateDevices')); } catch(e) { return false; }
                    })(),
                    payment_api: (function() {
                        try { return typeof PaymentRequest !== 'undefined' && (allCodes.includes('PaymentRequest') || allCodes.includes('new PaymentRequest')); } catch(e) { return false; }
                    })(),
                    service_worker: (function() {
                        try { return typeof navigator.serviceWorker !== 'undefined' && (allCodes.includes('serviceWorker') || allCodes.includes('navigator.serviceWorker.register')); } catch(e) { return false; }
                    })(),
                    localstorage_usage: (function() {
                        try { return typeof localStorage !== 'undefined' && localStorage.length > 0; } catch(e) { return false; }
                    })(),
                    sessionstorage_usage: (function() {
                        try { return typeof sessionStorage !== 'undefined' && sessionStorage.length > 0; } catch(e) { return false; }
                    })(),
                    indexeddb_usage: (function() {
                        try { return typeof indexedDB !== 'undefined' && (allCodes.includes('indexedDB') || allCodes.includes('indexeddb') || allCodes.includes('IDBFactory') || allCodes.includes('IDBOpenDBRequest')); } catch(e) { return false; }
                    })(),
                };
            }""")
            self.js_analysis = analysis
        except Exception as e:
            logger.warning("JS analysis failed: %s", e)
            self.js_analysis = {}

    def _analyze_security_headers(self):
        result = {}
        for key in SECURITY_HEADER_KEYS:
            val = self.final_headers.get(key, "")
            if not val:
                result[key] = {"status": "Missing", "value": ""}
            else:
                status = "Present"
                if key == "Content-Security-Policy":
                    if "unsafe-inline" in val or "unsafe-eval" in val or val == "*":
                        status = "Weak"
                elif key == "X-Frame-Options":
                    if val.upper() not in ("DENY", "SAMEORIGIN"):
                        status = "Weak"
                elif key == "Strict-Transport-Security":
                    m = re.search(r'max-age=(\d+)', val, re.I)
                    if m and int(m.group(1)) < 31536000:
                        status = "Weak"
                result[key] = {"status": status, "value": val[:500]}
        self.security_headers = result

    def _analyze_cookies(self):
        try:
            cookies = self._context.cookies()
            result = []
            for c in cookies:
                insecure_flags = []
                if not c.get("secure"):
                    insecure_flags.append("Missing Secure flag")
                if not c.get("httponly"):
                    insecure_flags.append("Missing HttpOnly flag")
                samesite = c.get("sameSite", "None")
                if not samesite or samesite == "none":
                    insecure_flags.append("Missing SameSite attribute")
                result.append({
                    "name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "path": c.get("path", ""),
                    "secure": bool(c.get("secure", False)),
                    "httponly": bool(c.get("httponly", False)),
                    "samesite": samesite or "None",
                    "expires": str(c.get("expires", "Session")) if c.get("expires") else "Session",
                    "flags_insecure": insecure_flags,
                })
            self.cookie_data = {
                "cookies": result,
                "count": len(result),
                "insecure_count": sum(1 for c in result if c["flags_insecure"]),
            }
        except Exception as e:
            logger.warning("Cookie analysis failed: %s", e)
            self.cookie_data = {"cookies": [], "count": 0, "insecure_count": 0}

    def _analyze_tls_with_socket(self):
        hostname = self.parsed.hostname
        port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        if self.parsed.scheme != "https":
            self.tls_info = {"used": False, "note": "Connection was not over HTTPS."}
            return

        sd = self.final_security_details or {}

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer_str = ", ".join(f"{k}={v}" for k, v in issuer.items())
                    cn = subject.get("commonName", "")
                    san = cert.get("subjectAltName", [])
                    san_list = [v for _, v in san]

                    expiry = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_remaining = (expiry - datetime.now(timezone.utc)).days
                    is_self_signed = issuer == subject
                    is_expired = days_remaining < 0
                    cipher_name = cipher[0] if cipher else ""
                    cipher_bits = int(cipher[2]) if cipher and len(cipher) > 2 else 0
                    weak_cipher = (
                        (isinstance(cipher_bits, (int, float)) and cipher_bits < 128)
                        or "RC4" in cipher_name
                        or "DES" in cipher_name
                        or "MD5" in cipher_name
                    )

                    self.tls_info = {
                        "used": True,
                        "tls_version": tls_version,
                        "cipher_suite": cipher_name,
                        "cipher_bits": cipher_bits,
                        "weak_cipher": weak_cipher,
                        "issuer": issuer_str,
                        "common_name": cn,
                        "subject_alt_names": san_list[:20],
                        "san_count": len(san_list),
                        "not_before": not_before,
                        "not_after": not_after,
                        "days_remaining": days_remaining,
                        "self_signed": is_self_signed,
                        "expired": is_expired,
                        "cert_valid": not is_expired and not is_self_signed,
                        "ocsp": "Not Checked (external)",
                        "cert_chain_count": len(cert.get("ca_issuers", [])) + 1,
                    }
                    logger.info(
                        "TLS analysis: version=%s, cipher=%s, issuer=%s, days=%d",
                        tls_version, cipher_name, issuer_str, days_remaining,
                    )
        except ssl.CertificateError as e:
            self.tls_info = {"used": True, "error": f"Certificate error: {e}"}
        except Exception as e:
            logger.warning("TLS socket analysis failed, using browser data: %s", e)
            browser_protocol = sd.get("protocol", "Unknown")
            browser_issuer = sd.get("issuer", "")
            browser_subject = sd.get("subjectName", "")
            valid_from = sd.get("validFrom")
            valid_to = sd.get("validTo")
            days_left = 0
            if valid_to:
                try:
                    exp = datetime.fromtimestamp(valid_to, tz=timezone.utc)
                    days_left = (exp - datetime.now(timezone.utc)).days
                except Exception:
                    pass
            self.tls_info = {
                "used": True,
                "tls_version": browser_protocol,
                "cipher_suite": "Not Available from browser",
                "issuer": browser_issuer,
                "common_name": browser_subject,
                "subject_alt_names": [],
                "san_count": 0,
                "days_remaining": days_left,
                "self_signed": False,
                "expired": days_left < 0,
                "cert_valid": days_left >= 0,
                "note": "Certificate details from browser (limited)",
            }

    def _analyze_network(self):
        total_requests = len(self.requests_log)
        images = sum(1 for r in self.requests_log if r["type"] == "image")
        fonts = sum(1 for r in self.requests_log if r["type"] == "font")
        scripts = sum(1 for r in self.requests_log if r["type"] == "script")
        stylesheets = sum(1 for r in self.requests_log if r["type"] == "stylesheet")
        xhr = sum(1 for r in self.requests_log if r["type"] == "xhr")
        fetch = sum(1 for r in self.requests_log if r["type"] == "fetch")
        media = sum(1 for r in self.requests_log if r["type"] in ("media", "audiovideo"))
        documents = sum(1 for r in self.requests_log if r["type"] == "document")
        other = sum(1 for r in self.requests_log if r["type"] not in (
            "image", "font", "script", "stylesheet", "xhr", "fetch", "media", "audiovideo", "document",
        ))

        redirect_count = len(self.redirect_chain_log)
        load_time_ms = 0
        if self.start_time and self.end_time:
            load_time_ms = round((self.end_time - self.start_time) * 1000, 1)

        largest_resource = ""
        largest_size = 0
        slowest_resource = ""
        slowest_time = 0

        resp_by_url = {}
        for r in self.responses_log:
            resp_by_url[r["url"]] = r

        total_size = 0
        for req in self.requests_log:
            url = req["url"]
            resp = resp_by_url.get(url)
            if resp:
                content_length = int(resp["headers"].get("content-length", 0) or 0)
                total_size += content_length
                if content_length > largest_size:
                    largest_size = content_length
                    largest_resource = url[:200]

        self.performance_metrics = {
            "total_requests": total_requests,
            "images": images,
            "fonts": fonts,
            "scripts": scripts,
            "stylesheets": stylesheets,
            "xhr": xhr,
            "fetch": fetch,
            "media": media,
            "documents": documents,
            "other": other,
            "redirect_count": redirect_count,
            "largest_resource": largest_resource or "Not Available",
            "largest_resource_bytes": largest_size,
            "slowest_resource": slowest_resource or "Not Available",
            "total_transfer_size": total_size,
            "load_time_ms": load_time_ms,
        }

    def _analyze_resource_breakdown(self):
        third_party_domains = {}
        resources_by_type = {
            "scripts": [],
            "stylesheets": [],
            "images": [],
            "fonts": [],
            "media": [],
            "xhr": [],
            "fetch": [],
            "documents": [],
            "other": [],
        }
        sizes_by_type = {
            "scripts": 0,
            "stylesheets": 0,
            "images": 0,
            "fonts": 0,
            "media": 0,
            "xhr": 0,
            "fetch": 0,
            "documents": 0,
            "other": 0,
        }

        resp_by_url = {}
        for r in self.responses_log:
            resp_by_url[r["url"]] = r

        for req in self.requests_log:
            rtype = req["type"]
            url = req["url"]
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            size = 0
            resp = resp_by_url.get(url)
            if resp:
                size = int(resp["headers"].get("content-length", 0) or 0)

            if domain and domain != self.parsed.netloc:
                third_party_domains[domain] = third_party_domains.get(domain, 0) + 1

            type_key = rtype
            if rtype in ("media", "audiovideo"):
                type_key = "media"
            if type_key in resources_by_type:
                resources_by_type[type_key].append({
                    "url": url[:200],
                    "size": size,
                })
                sizes_by_type[type_key] += size

        largest_resources = []
        all_resources = []
        for req in self.requests_log:
            url = req["url"]
            resp = resp_by_url.get(url)
            size = 0
            if resp:
                size = int(resp["headers"].get("content-length", 0) or 0)
            if size > 0:
                all_resources.append({"url": url[:200], "size": size})

        all_resources.sort(key=lambda x: x["size"], reverse=True)
        largest_resources = all_resources[:10]

        third_party_sorted = sorted(
            third_party_domains.items(), key=lambda x: x[1], reverse=True
        )[:20]

        self.resource_summary = {
            "images": len(resources_by_type["images"]),
            "css": len(resources_by_type["stylesheets"]),
            "javascript": len(resources_by_type["scripts"]),
            "fonts": len(resources_by_type["fonts"]),
            "media": len(resources_by_type["media"]),
            "xhr": len(resources_by_type["xhr"]),
            "fetch": len(resources_by_type["fetch"]),
            "documents": len(resources_by_type["documents"]),
            "other": len(resources_by_type["other"]),
            "total": sum(len(v) for v in resources_by_type.values()),
            "total_size": sum(v for v in sizes_by_type.values()),
            "third_party_domains": third_party_sorted,
            "largest_resources": largest_resources,
            "sizes": sizes_by_type,
        }

    def _detect_technologies(self):
        detected = set()
        html_lower = self.page_html.lower() if self.page_html else ""
        all_headers_lower = {k.lower(): v.lower() for k, v in self.final_headers.items()}

        for name, patterns in TECH_PATTERNS.items():
            for pat in patterns:
                if ":" in pat and pat.startswith("Server:") is False and pat.startswith("x-powered-by:") is False:
                    continue
                if pat.startswith("Server:") or pat.startswith("x-powered-by:"):
                    key = pat.split(":")[0].strip().lower()
                    val = pat.split(":")[1].strip()
                    if key in all_headers_lower and val in all_headers_lower[key]:
                        detected.add(name)
                        break
                else:
                    if re.search(pat, html_lower, re.I):
                        detected.add(name)
                        break

        try:
            js_globals = self._page.evaluate("""() => {
                const g = {};
                try { g.React = typeof React !== 'undefined'; } catch(e) {}
                try { g.Vue = typeof Vue !== 'undefined'; } catch(e) {}
                try { g.Angular = typeof angular !== 'undefined'; } catch(e) {}
                try { g.jQuery = typeof jQuery !== 'undefined' || typeof $ !== 'undefined'; } catch(e) {}
                try { g.NextJS = !!document.getElementById('__NEXT_DATA__'); } catch(e) {}
                try { g.Nuxt = !!document.getElementById('__NUXT_DATA__') || window.__NUXT__; } catch(e) {}
                return g;
            }""")
            if js_globals.get("React"):
                detected.add("React")
            if js_globals.get("Vue"):
                detected.add("Vue")
            if js_globals.get("Angular"):
                detected.add("Angular")
            if js_globals.get("jQuery"):
                detected.add("jQuery")
            if js_globals.get("NextJS"):
                detected.add("Next.js")
            if js_globals.get("Nuxt"):
                detected.add("Nuxt")
        except Exception as e:
            logger.warning("JS global detection failed: %s", e)

        self.tech_list = sorted(detected)

    def _capture_screenshot(self):
        try:
            screenshot_bytes = self._page.screenshot(type="png", full_page=False)
            self.screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
        except Exception as e:
            logger.warning("Screenshot capture failed: %s", e)
            self.screenshot_b64 = None

    def _sanitize_html(self):
        html = self.page_html
        if not html:
            self.sanitized_html = ""
            return

        def fix_url(match):
            attr = match.group(1)
            val = match.group(2)
            if any(val.startswith(p) for p in ("http", "//", "data:", "#", "javascript:", "mailto:", "tel:")):
                return match.group(0)
            if val.startswith("/"):
                return f'{attr}="{self.base_origin}{val}"'
            return f'{attr}="{self.base_origin}/{val}"'

        html = re.sub(r'(src|href)="([^"]*)"', fix_url, html)
        html = re.sub(r"(src|href)='([^']*)'", fix_url, html)
        html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<iframe[^>]*>.*?</iframe>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<noscript[^>]*>.*?</noscript>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<(?:embed|object)[^>]*>.*?</(?:embed|object)>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<form[^>]*>.*?</form>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r'\s+on\w+\s*=\s*"[^"]*"', "", html, flags=re.IGNORECASE)
        html = re.sub(r"\s+on\w+\s*=\s*'[^']*'", "", html, flags=re.IGNORECASE)
        html = re.sub(r"\s+on\w+\s*=\s*[^\s>]+", "", html, flags=re.IGNORECASE)
        html = re.sub(r'\s+href\s*=\s*"(?:javascript|data|vbscript):[^"]*"', ' href="#"', html, flags=re.IGNORECASE)
        html = re.sub(r"\s+href\s*=\s*'(?:javascript|data|vbscript):[^']*'", " href='#'", html, flags=re.IGNORECASE)

        self.sanitized_html = html

    def _calculate_risk(self):
        score = 100
        deductions_list = []

        def deduct(points, title, desc, evidence="", recommendation="", reference=""):
            nonlocal score
            score -= points
            deductions_list.append({
                "points": points,
                "title": title,
                "description": desc,
                "evidence": evidence,
                "recommendation": recommendation,
                "reference": reference,
            })

        if self.parsed.scheme != "https":
            deduct(35, "No HTTPS", "Connection uses plain HTTP instead of HTTPS.",
                   f"URL: {self.url}",
                   "Redirect all traffic to HTTPS using a 301 redirect.",
                   "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security")

        mixed = re.findall(r'src\s*=\s*["\']http://', self.page_html, re.I)
        mixed += re.findall(r'href\s*=\s*["\']http://', self.page_html, re.I)
        if mixed:
            deduct(20, "Mixed Content", f"Page loads {len(mixed)} resources over insecure HTTP.",
                   f"Found {len(mixed)} HTTP URLs on HTTPS page",
                   "Use HTTPS URLs for all resources.",
                   "https://developer.mozilla.org/docs/Web/Security/Mixed_content")

        tls = self.tls_info
        if tls.get("expired"):
            deduct(40, "Invalid Certificate", "The SSL certificate has expired.",
                   f"Expired: {tls.get('not_after', 'unknown')}",
                   "Renew the SSL certificate immediately.",
                   "https://www.digicert.com/kb/ssl-certificate-expiration.htm")
        if tls.get("self_signed"):
            deduct(25, "Self-Signed Certificate", "The server uses a self-signed certificate.",
                   f"Issuer: {tls.get('issuer', 'unknown')}",
                   "Replace with a certificate from a trusted CA.",
                   "https://www.digicert.com/kb/certificate-authority.htm")

        csp = self.security_headers.get("Content-Security-Policy", {})
        if csp.get("status") == "Missing":
            deduct(10, "Missing CSP", "No Content-Security-Policy header.",
                   "HTTP response headers lack CSP",
                   "Implement a restrictive CSP header to mitigate XSS.",
                   "https://developer.mozilla.org/docs/Web/HTTP/CSP")

        sts = self.security_headers.get("Strict-Transport-Security", {})
        if sts.get("status") == "Missing" and self.parsed.scheme == "https":
            deduct(10, "Missing HSTS", "No Strict-Transport-Security header.",
                   "HTTP response headers lack HSTS",
                   "Enable HSTS with a long max-age directive.",
                   "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security")

        xfo = self.security_headers.get("X-Frame-Options", {})
        if xfo.get("status") == "Missing":
            deduct(5, "Missing X-Frame-Options", "Page can be embedded in iframes (clickjacking risk).",
                   "HTTP response headers lack X-Frame-Options",
                   "Add X-Frame-Options: DENY or SAMEORIGIN.",
                   "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options")
        xcto = self.security_headers.get("X-Content-Type-Options", {})
        if xcto.get("status") == "Missing":
            deduct(3, "Missing X-Content-Type-Options", "Browser may MIME-sniff responses.",
                   "HTTP response headers lack X-Content-Type-Options",
                   "Add X-Content-Type-Options: nosniff.",
                   "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options")

        if self.dom_stats.get("external_scripts", 0) > 15:
            deduct(5, "Excessive External Scripts",
                   f"Page loads {self.dom_stats.get('external_scripts', 0)} external scripts.",
                   f"Found {self.dom_stats.get('external_scripts', 0)} <script src=...> tags",
                   "Limit third-party scripts to essential services.",
                   "https://developer.mozilla.org/docs/Web/HTML/Element/script")

        if self.dom_stats.get("inline_scripts", 0) > 0:
            deduct(5, "Inline JavaScript", "Page contains inline script blocks (XSS risk).",
                   f"Found {self.dom_stats.get('inline_scripts', 0)} inline <script> blocks",
                   "Move inline scripts to external JS files and implement CSP.",
                   "https://developer.mozilla.org/docs/Web/HTTP/CSP")

        js = self.js_analysis or {}
        if js.get("eval_usage"):
            deduct(20, "eval() Usage Detected", "Page uses eval() which can execute arbitrary code.",
                   "Found eval() in page scripts",
                   "Avoid eval(). Use JSON.parse for JSON, or Function constructors safely.",
                   "https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval")
        if js.get("document_write"):
            deduct(10, "document.write() Usage", "Page uses document.write() which is unsafe.",
                   "Found document.write() in page scripts",
                   "Replace with DOM manipulation methods.",
                   "https://developer.mozilla.org/docs/Web/API/Document/write")

        if self.dom_stats.get("iframes", 0) > 0:
            unsafe_iframes = 0
            try:
                unsafe_iframes = self._page.evaluate(
                    """() => [...document.querySelectorAll('iframe')].filter(
                        f => !f.sandbox || !f.sandbox.length).length"""
                )
            except Exception:
                pass
            if unsafe_iframes > 0:
                deduct(10, "Unsafe Iframes", f"{unsafe_iframes} iframe(s) missing sandbox attribute.",
                       f"Found {unsafe_iframes} iframe(s) without sandbox",
                       "Add sandbox attribute to all iframes.",
                       "https://developer.mozilla.org/docs/Web/HTML/Element/iframe#attr-sandbox")

        if js.get("service_worker"):
            deduct(3, "Service Worker Registered", "Page registers a service worker.",
                   "navigator.serviceWorker is available",
                   "Review service worker scope and behavior.",
                   "https://developer.mozilla.org/docs/Web/API/Service_Worker_API")
        if js.get("clipboard_api"):
            deduct(2, "Clipboard API Usage", "Page can read/write clipboard.",
                   "navigator.clipboard API detected in page scripts",
                   "Restrict clipboard access to user-initiated actions.",
                   "https://developer.mozilla.org/docs/Web/API/Clipboard_API")
        if js.get("geolocation_api"):
            deduct(5, "Geolocation API Usage", "Page requests user location.",
                   "navigator.geolocation API detected in page scripts",
                   "Only request location when absolutely necessary.",
                   "https://developer.mozilla.org/docs/Web/API/Geolocation_API")
        if js.get("camera_api"):
            deduct(10, "Camera API Usage", "Page can access camera.",
                   "mediaDevices.getUserMedia detected in page scripts",
                   "Only request camera access when user initiates action.",
                   "https://developer.mozilla.org/docs/Web/API/MediaDevices/getUserMedia")
        if js.get("microphone_api"):
            deduct(10, "Microphone API Usage", "Page can access microphone.",
                   "mediaDevices.getUserMedia (audio) detected in page scripts",
                   "Only request microphone access when necessary.",
                   "https://developer.mozilla.org/docs/Web/API/MediaDevices/getUserMedia")
        if js.get("notification_api"):
            deduct(2, "Notification API Usage", "Page can send notifications.",
                   "Notification API detected in page scripts",
                   "Request notification permission with user gesture.",
                   "https://developer.mozilla.org/docs/Web/API/Notification")
        if js.get("payment_api"):
            deduct(5, "Payment API Usage", "Page uses Payment Request API.",
                   "PaymentRequest API detected in page scripts",
                   "Ensure payment requests are user-initiated.",
                   "https://developer.mozilla.org/docs/Web/API/Payment_Request_API")
        if js.get("websocket_usage"):
            deduct(5, "WebSocket Usage", "Page establishes WebSocket connections.",
                   "WebSocket API detected in page scripts",
                   "Ensure WebSocket connections use secure wss:// protocol.",
                   "https://developer.mozilla.org/docs/Web/API/WebSocket")
        if js.get("webrtc_usage"):
            deduct(5, "WebRTC Usage", "Page uses WebRTC (possible data exfiltration).",
                   "RTCPeerConnection API detected in page scripts",
                   "Restrict WebRTC to trusted origins only.",
                   "https://developer.mozilla.org/docs/Web/API/WebRTC_API")

        count_third_party = len(self.resource_summary.get("third_party_domains", []))
        if count_third_party > 5:
            deduct(
                5, "Third-Party Tracking Scripts",
                f"Page loads resources from {count_third_party} third-party domains.",
                f"Third-party domains: {', '.join(d[0] for d in self.resource_summary.get('third_party_domains', [])[:5])}",
                "Audit third-party resources and remove unnecessary tracking.",
                "https://developer.mozilla.org/docs/Web/Privacy/Third-party_cookies",
            )

        score = max(0, min(100, score))

        risk_level = "Critical"
        if score >= 90:
            risk_level = "Safe"
        elif score >= 70:
            risk_level = "Low Risk"
        elif score >= 50:
            risk_level = "Moderate"
        elif score >= 30:
            risk_level = "High"

        self.security_result = {
            "score": score,
            "risk_level": risk_level,
            "deductions": sum(d["points"] for d in deductions_list),
            "deductions_list": deductions_list,
            "findings": [],
        }

        for d in deductions_list:
            severity_map = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}
            severity = "Low"
            if d["points"] >= 30:
                severity = "Critical"
            elif d["points"] >= 15:
                severity = "High"
            elif d["points"] >= 5:
                severity = "Medium"

            finding = {
                "severity": severity,
                "title": d["title"],
                "description": d["description"],
                "evidence": d.get("evidence", ""),
                "recommendation": d.get("recommendation", ""),
                "reference": d.get("reference", ""),
            }
            self.security_result["findings"].append(finding)

    def _get_removed_elements(self):
        removed = []
        orig_scripts = self.dom_stats.get("scripts", 0)
        orig_iframes = self.dom_stats.get("iframes", 0)
        orig_forms = self.dom_stats.get("forms", 0)
        if orig_scripts:
            removed.append({
                "type": "SCRIPT",
                "source": f"{orig_scripts} scripts removed",
                "reason": "JavaScript execution blocked",
            })
        if orig_iframes:
            removed.append({
                "type": "IFRAME",
                "source": f"{orig_iframes} iframes removed",
                "reason": "Embedded remote content blocked",
            })
        if orig_forms:
            removed.append({
                "type": "FORM",
                "source": f"{orig_forms} forms removed",
                "reason": "Credential collection disabled",
            })
        return removed

    def _get_redirect_analysis(self):
        chain = []
        for entry in self.redirect_chain_log:
            parsed_from = urlparse(entry["url"])
            parsed_to = urlparse(entry.get("location", ""))
            protocol_change = (
                "Yes" if parsed_from.scheme != parsed_to.scheme else "No"
            ) if parsed_to.scheme else "Unknown"
            chain.append({
                "status_code": entry["status"],
                "from_url": entry["url"],
                "location": entry.get("location", ""),
                "protocol_change": protocol_change,
            })
        return chain

    def scan(self):
        self.start_time = time.monotonic()
        result = {"success": True}

        try:
            self._ensure_browser()
            self._create_context()
            self._page = self._context.new_page()
            self._setup_network_listeners()

            try:
                response = self._page.goto(
                    self.url,
                    wait_until="networkidle",
                    timeout=NAV_TIMEOUT,
                )
                if response:
                    self.final_url_value = response.url
                    self.final_status_code = response.status
                    self.final_headers = dict(response.headers)
                    self.final_security_details = response.security_details() or {}
                else:
                    self.final_url_value = self._page.url
                    self.final_status_code = None
            except Exception as e:
                logger.warning("Navigation error for %s: %s", self.url, e)
                self.final_url_value = self._page.url if self._page else self.url
                self.has_partial = True
                if "Timeout" in str(e):
                    self.error_message = "Page load timed out. Partial results shown."

            self.end_time = time.monotonic()

            if self._page:
                try:
                    self.page_html = self._page.content()
                except Exception as e:
                    logger.warning("Failed to get page content: %s", e)
                    self.page_html = ""

                self._extract_metadata()
                self._extract_dom_stats()
                self._extract_js_analysis()
                self._capture_screenshot()

            if not self.final_headers and self.responses_log:
                last_resp = self.responses_log[-1]
                self.final_url_value = last_resp["url"]
                self.final_status_code = last_resp["status"]
                self.final_headers = last_resp["headers"]
                self.final_security_details = last_resp.get("security_details", {})

            self._analyze_security_headers()
            self._analyze_cookies()
            self._analyze_tls_with_socket()
            self._analyze_network()
            self._analyze_resource_breakdown()
            self._detect_technologies()
            self._sanitize_html()
            self._calculate_risk()

            sec_headers_flat = {}
            for k, v in self.security_headers.items():
                sec_headers_flat[k] = {"status": v["status"], "value": v.get("value", "")}

            redirect_chain = self._get_redirect_analysis()

            request_info = {
                "url": self.url,
                "method": "GET",
                "user_agent": "Playwright Chromium (Headless Chrome 120)",
            }

            http_info = {
                "status_code": self.final_status_code,
                "reason": "",
                "redirect_count": len(self.redirect_chain_log),
                "redirect_chain": redirect_chain,
                "server": self.final_headers.get("Server", ""),
                "content_type": self.final_headers.get("Content-Type", ""),
            }

            external_sources = self.dom_stats.get("external_sources", [])

            result = {
                "success": True,
                "request": request_info,
                "final_url": self.final_url_value or self.url,
                "http": http_info,
                "page_metadata": self.page_metadata,
                "dom_statistics": self.dom_stats,
                "link_analysis": self.link_analysis or {
                    "internal": 0, "external": 0, "mailto": 0, "telephone": 0,
                    "javascript": 0, "download": 0, "redirect": 0, "total": 0,
                },
                "script_analysis": {
                    "external_scripts": self.dom_stats.get("external_scripts", 0),
                    "inline_scripts": self.dom_stats.get("inline_scripts", 0),
                    "external_sources": external_sources,
                    "analysis": {
                        "eval_usage": 1 if self.js_analysis.get("eval_usage") else 0,
                        "document_write": 1 if self.js_analysis.get("document_write") else 0,
                        "new_function": 0,
                        "set_timeout_string": 1 if self.js_analysis.get("setTimeout_string") else 0,
                        "set_interval_string": 1 if self.js_analysis.get("setInterval_string") else 0,
                        "base64_encoded": 0,
                        "obfuscated": 0,
                        "suspicious_inline": 0,
                    },
                    "suspicion_score": 0,
                    "external_sources": external_sources,
                },
                "js_analysis": self.js_analysis,
                "security_headers": sec_headers_flat,
                "cookie_analysis": self.cookie_data,
                "technologies": self.tech_list,
                "tls_analysis": self.tls_info,
                "performance": self.performance_metrics,
                "resource_summary": self.resource_summary,
                "security": self.security_result,
                "network_analysis": self.performance_metrics,
                "resource_breakdown": self.resource_summary,
                "redirect_analysis": redirect_chain,
                "sanitized_html": self.sanitized_html,
                "screenshot_b64": self.screenshot_b64,
                "original_size": len(self.page_html),
                "sanitized_size": len(self.sanitized_html),
                "removed_elements": self._get_removed_elements(),
                "cookie_data": self.cookie_data,
                "has_partial": self.has_partial,
            }

            if self.error_message:
                result["warning"] = self.error_message

        except Exception as e:
            logger.exception("Scan failed for %s", self.url)
            result = {
                "success": False,
                "error": f"Scan failed: {str(e)}",
            }
        finally:
            self._cleanup()

        return result

    def _cleanup(self):
        try:
            if self._page:
                self._page.close()
        except Exception:
            pass
        try:
            if self._context:
                self._context.close()
        except Exception:
            pass
        self._page = None
        self._context = None
