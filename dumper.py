#!/usr/bin/env python3
"""page_dumper — recon tool for grabbing and analyzing web page sources."""

import argparse
import hashlib
import ipaddress
import json
import random
import re
import sys
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment
from colorama import Fore, Style, init as colorama_init
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

MAX_PARSE_SIZE = 5 * 1024 * 1024
MAX_DOWNLOAD_SIZE = 20 * 1024 * 1024
RE_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class Resource:
    __slots__ = ("url", "content", "rtype", "source", "filename", "external", "saved")

    def __init__(self, url: str, rtype: str, source: str = "",
                 content: str = "", filename: str = "", external: bool = False):
        self.url = url
        self.rtype = rtype
        self.source = source
        self.content = content
        self.filename = filename
        self.external = external
        self.saved = False


# ---------------------------------------------------------------------------
#  Regex patterns
# ---------------------------------------------------------------------------

RE_URL = re.compile(r"""(?:https?://|wss?://)[^\s'"<>)\]},]+""", re.I)
RE_PATH = re.compile(
    r"""['"`](/(?:api|v[0-9]|graphql|rest|auth|admin|user|login|register"""
    r"""|upload|download|config|settings|internal|debug|swagger|docs)"""
    r"""[^\s'"<>)\]},]*?)['"`]""", re.I,
)
RE_ENDPOINT = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`]+)['"`]""", re.I),
    re.compile(r"""\.open\s*\(\s*['"][^'"]*['"]\s*,\s*['"`]([^'"`]+)['"`]""", re.I),
    re.compile(r"""(?:baseURL|baseUrl|BASE_URL)\s*[:=]\s*['"`]([^'"`]{4,})['"`]""", re.I),
]
RE_SECRETS = {
    "API Key":         re.compile(r"""(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]""", re.I),
    "Token/Secret":    re.compile(r"""(?:(?:access_?)?token|secret|password|passwd|pwd|auth_key)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]""", re.I),
    "AWS Access Key":  re.compile(r"""(AKIA[0-9A-Z]{16})"""),
    "JWT":             re.compile(r"""(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.\-_+/=]+)"""),
    "Private Key":     re.compile(r"""(-----BEGIN[\s\w]*PRIVATE KEY-----)"""),
    "Google API Key":  re.compile(r"""(AIza[0-9A-Za-z_-]{35})"""),
    "GitHub Token":    re.compile(r"""(gh[pousr]_[A-Za-z0-9_]{36,})"""),
    "Slack Token":     re.compile(r"""(xox[baprs]-[0-9A-Za-z\-]+)"""),
    "Hardcoded IP":    re.compile(r"""(?<![.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?"""),
    "Email":           re.compile(r"""([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"""),
}
RE_SOURCEMAP = re.compile(r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""")
RE_JS_IMPORT = [
    re.compile(r"""import\s+.*?from\s+['"]([^'"]+\.js(?:\?[^'"]*)?)['"]\s*;"""),
    re.compile(r"""(?:require|import)\s*\(\s*['"]([^'"]+\.js(?:\?[^'"]*)?)['"]\s*\)"""),
    re.compile(r"""(?:importScripts|Worker)\s*\(\s*['"]([^'"]+\.js(?:\?[^'"]*)?)['"]\s*\)"""),
    re.compile(r"""['"]([^'"]*\.chunk\.js(?:\?[^'"]*)?)['"]"""),
]
RE_CONFIG = re.compile(
    r"""window\.(?:__(?:CONFIG|INITIAL_STATE|NEXT_DATA|NUXT__|APP_DATA)__|"""
    r"""config|settings|appConfig|ENV)\s*=\s*(\{[\s\S]*?\});""", re.I,
)
RE_CSS_URL = re.compile(r"""url\(\s*['"]?([^'"\)\s]+)['"]?\s*\)""", re.I)

DOM_SINKS = {
    "innerHTML/outerHTML":     re.compile(r"""\.(?:inner|outer)HTML\s*[=+]"""),
    "document.write":          re.compile(r"""document\.write(?:ln)?\s*\("""),
    "eval()":                  re.compile(r"""(?:^|[^.\w])eval\s*\(""", re.M),
    "Function()":              re.compile(r"""new\s+Function\s*\("""),
    "setTimeout(string)":      re.compile(r"""(?:setTimeout|setInterval)\s*\(\s*['"`]"""),
    "location manipulation":   re.compile(r"""(?:location|document\.location)\s*(?:\.\s*(?:href|assign|replace)\s*[=(]|=)"""),
    "postMessage":             re.compile(r"""\.postMessage\s*\("""),
    "message listener":        re.compile(r"""addEventListener\s*\(\s*['"]message['"]"""),
    "dangerouslySetInnerHTML": re.compile(r"""dangerouslySetInnerHTML"""),
    "document.domain":         re.compile(r"""document\.domain\s*="""),
    "jquery .html()":          re.compile(r"""\.\s*html\s*\(\s*[^)]"""),
}

INTERESTING_KEYWORDS = frozenset({
    "admin", "password", "passwd", "secret", "token", "apikey", "api_key",
    "auth", "authorization", "credential", "private", "internal", "debug",
    "backdoor", "bypass", "master", "root", "superuser", "sudo", "hidden",
    "encrypt", "decrypt", "ssn", "credit_card", "payment",
})
JSON_KEY_HINTS = frozenset({
    "url", "api", "endpoint", "host", "domain", "server", "path", "href",
    "redirect", "callback", "webhook", "origin", "base", "gateway",
})

TECH_SIGNATURES = {
    "React": [r"react", r"__REACT", r"_reactRoot"],
    "Angular": [r"ng-app", r"ng-controller", r"angular\.module"],
    "Vue.js": [r"__vue__", r"v-bind", r"v-model", r"vue[\./]"],
    "jQuery": [r"jquery\.?(?:min)?\.js"],
    "Next.js": [r"__NEXT_DATA__", r"_next/"],
    "Nuxt.js": [r"__NUXT__", r"_nuxt/"],
    "WordPress": [r"wp-content", r"wp-includes"],
    "Webpack": [r"webpackChunk", r"__webpack_require__"],
    "Svelte": [r"svelte", r"__svelte"],
}
SECURITY_HEADERS = [
    "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
    "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy",
    "Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
]
EXTRA_FILES = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "crossdomain.xml", "humans.txt",
]
GIT_FILES = [
    "HEAD", "config", "description", "packed-refs",
    "refs/heads/master", "refs/heads/main", "refs/heads/develop",
    "refs/remotes/origin/HEAD",
    "logs/HEAD", "logs/refs/heads/master", "logs/refs/heads/main",
    "info/refs", "info/exclude", "COMMIT_EDITMSG",
]
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-request-id"],
    "AWS WAF": ["awselb", "x-amzn-requestid", "x-amz-apigw-id"],
    "Akamai": ["akamai", "x-akamai", "akamaighost"],
    "Imperva/Incapsula": ["incapsula", "imperva", "x-iinfo", "visid_incap"],
    "ModSecurity": ["mod_security", "modsecurity", "naxsi"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "F5 BIG-IP": ["bigipserver", "x-cnection"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "DDoS-Guard": ["ddos-guard"],
    "Wordfence": ["wordfence"],
}
BRUTEFORCE_PATHS = [
    "/admin", "/administrator", "/admins", "/admin.php", "/adminarea",
    "/adminportal", "/cp", "/manager", "/management", "/dashboard",
    "/backend", "/console", "/modules", "/setup",
    "/install", "/install.php",
    "/.git", "/.git/HEAD", "/.git/config",
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/dump.sql", "/db_backup.sql", "/.htaccess", "/.htpasswd",
    "/config.php", "/config.js", "/config.json", "/configuration.php",
    "/web.config", "/composer.json", "/package.json", "/package-lock.json",
    "/yarn.lock", "/Gemfile",
    "/api", "/api/v1", "/api/v2", "/api/docs", "/api/swagger",
    "/swagger", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/graphql", "/graphiql", "/rest", "/rest/v1",
    "/openapi.json", "/openapi.yaml",
    "/api/health", "/api/status", "/api/config", "/api/debug",
    "/phpinfo.php", "/info.php", "/test.php", "/test",
    "/phpmyadmin", "/pma", "/mysql", "/myadmin",
    "/server-status", "/server-info", "/status",
    "/cgi-bin/", "/.well-known/", "/.well-known/openid-configuration",
    "/logs/", "/logs/error.log", "/access.log", "/debug.log", "/error.log",
    "/tmp/", "/temp/", "/uploads/", "/files/",
    "/storage/", "/cache/", "/media/",
    "/wp-admin/", "/wp-content/", "/wp-includes/",
    "/wp-json/", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-login.php", "/wp-config.php.bak",
    "/administrator/index.php",
    "/_ignition/health-check", "/telescope/", "/horizon/",
    "/_next/", "/.next/",
    "/readme.html", "/README.md", "/CHANGELOG.md",
]


_UA_POOL = [
    # Chrome Win
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox Win
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # --- level 1: 10 UAs ---
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    # --- level 2: 16 UAs ---
    # Edge Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
    # Mobile Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    # Mobile Samsung
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    # --- level 3: 20 UAs ---
]
_ACCEPT_LANGS = [
    "en-US,en;q=0.9", "en-GB,en;q=0.9",
    "en-US,en;q=0.9,de;q=0.8", "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,es;q=0.8", "en-US,en;q=0.9,ja;q=0.8",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
]
_STEALTH_CFG = {
    1: {"threads": 5, "delay": (1.0, 1.0), "ua_count": 10},
    2: {"threads": 3, "delay": (1.0, 3.0), "ua_count": 16},
    3: {"threads": 1, "delay": (3.0, 5.0), "ua_count": 20},
}

_HTML_CSS = (
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,"
    "'Segoe UI',Helvetica,Arial,sans-serif;padding:24px;max-width:1200px;margin:0 auto}"
    "header{border-bottom:1px solid #30363d;padding-bottom:16px;margin-bottom:24px}"
    "h1{color:#f0f6fc;font-size:24px}h2{color:#f0f6fc;font-size:18px;margin-bottom:12px}"
    ".m{color:#8b949e;font-size:14px;margin-top:4px}"
    "nav{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}"
    "nav a{color:#58a6ff;text-decoration:none;font-size:14px;padding:4px 12px;"
    "border:1px solid #30363d;border-radius:16px}nav a:hover{border-color:#58a6ff}"
    "section{background:#161b22;border:1px solid #30363d;border-radius:8px;"
    "padding:20px;margin-bottom:16px}"
    ".cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:12px}"
    ".cd{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}"
    ".cv{font-size:28px;font-weight:700}.cl{font-size:12px;color:#8b949e;margin-top:4px}"
    ".chart{display:flex;gap:24px;align-items:flex-start}.bars{flex:1}"
    ".br{display:flex;align-items:center;margin-bottom:6px}"
    ".bl{width:160px;font-size:13px;color:#8b949e;flex-shrink:0}"
    ".bt{flex:1;background:#21262d;border-radius:4px;height:18px;overflow:hidden}"
    ".b{height:100%;border-radius:4px;min-width:2px}"
    ".tags{display:flex;flex-wrap:wrap;gap:8px}"
    ".tg{padding:4px 12px;border-radius:16px;font-size:13px;font-weight:600}"
    ".g{background:#238636;color:#fff}.r{background:#da3633;color:#fff}"
    "table{width:100%;border-collapse:collapse;font-size:13px}"
    "th{background:#21262d;color:#f0f6fc;text-align:left;padding:8px 12px;"
    "border-bottom:2px solid #30363d;position:sticky;top:0}"
    "td{padding:6px 12px;border-bottom:1px solid #21262d;vertical-align:top}"
    "tr:hover{background:#1c2128}"
    ".ok td:first-child{color:#3fb950;font-weight:700}"
    ".wn td:first-child{color:#d29922;font-weight:700}"
    ".sv{background:#3d1416;color:#ff7b72;padding:2px 6px;border-radius:4px;"
    "font-family:monospace;word-break:break-all}"
    ".sr{color:#8b949e;font-size:12px;max-width:300px;overflow:hidden;"
    "text-overflow:ellipsis;white-space:nowrap}"
    "code{background:#21262d;padding:2px 6px;border-radius:4px;font-size:12px;word-break:break-all}"
    "pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;"
    "overflow-x:auto;font-size:13px;max-height:400px;overflow-y:auto;"
    "white-space:pre-wrap;word-break:break-all}"
    "details summary{cursor:pointer;user-select:none}"
    "details summary:hover{color:#58a6ff}"
    ".tw{overflow-x:auto;max-height:60vh;overflow-y:auto}"
    "@media(max-width:768px){.chart{flex-direction:column}.bl{width:120px}}"
)
_CHART_COLORS = {
    "html": "#238636", "js": "#f0883e", "css": "#58a6ff",
    "inline_js": "#d29922", "inline_css": "#79c0ff",
    "sourcemap": "#a371f7", "extracted_src": "#bc8cff",
    "api_response": "#3fb950", "bruteforce": "#da3633",
    "wayback": "#1f6feb", "git": "#f778ba", "extra": "#8b949e",
}


class PageDumper:
    def __init__(self, *, url: str, output: Optional[str] = None, depth: int = 1,
                 onefile: bool = False, timeout: int = 15,
                 user_agent: Optional[str] = None, fetch_extras: bool = True,
                 headers: Optional[dict] = None, cookies: Optional[str] = None,
                 proxy: Optional[str] = None, insecure: bool = False,
                 bruteforce: bool = False, threads: int = 10,
                 host_header: Optional[str] = None,
                 json_report: bool = False, html_report: bool = False,
                 wayback: bool = False, delay: float = 0,
                 stealth: int = 0, log_path: Optional[str] = None):
        self.base_url = url.rstrip("/")
        self.parsed = urlparse(self.base_url)
        self.netloc = self.parsed.netloc
        self.base_origin = f"{self.parsed.scheme}://{self.netloc}"
        hostname = self.parsed.hostname or ""
        self.is_ip = _is_ip(hostname)

        if self.is_ip:
            self.root_domain = hostname
            self.re_subdomain = None
        else:
            parts = hostname.split(".")
            self.root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            self.re_subdomain = re.compile(
                rf"([a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.root_domain)})"
            )

        self.depth = depth
        self.onefile = onefile
        self.timeout = timeout
        self.fetch_extras = fetch_extras
        self.bruteforce = bruteforce
        self.threads = threads
        self.json_report = json_report
        self.html_report = html_report
        self.wayback = wayback
        self.delay = delay
        self._stealth = stealth
        self._rate_lock = threading.Lock()
        self._last_req = 0.0
        self._log_fh = open(log_path, "w", encoding="utf-8") if log_path else None

        if stealth >= 1:
            self.bruteforce = False
            scfg = _STEALTH_CFG[min(stealth, 3)]
            self.threads = min(self.threads, scfg["threads"])
            self._ua_pool = _UA_POOL[:scfg["ua_count"]]
        else:
            self._ua_pool = []

        self.session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers["User-Agent"] = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        if host_header:
            self.session.headers["Host"] = host_header
        if headers:
            self.session.headers.update(headers)
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if insecure:
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if stealth >= 1:
            self.session.headers.update({
                "Accept": "text/html,application/xhtml+xml,application/xml;"
                          "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "max-age=0",
                "DNT": "1",
            })

        if output:
            self.out = Path(output)
        else:
            slug = re.sub(r"[^\w.\-]", "_", self.netloc)
            self.out = Path(f"{slug}_{datetime.now():%y%m%d_%H%M%S}")

        self.resources: list[Resource] = []
        self.urls: set[str] = set()
        self.endpoints: set[str] = set()
        self.secrets: list[tuple[str, str, str]] = []
        self.configs: list[tuple[str, str]] = []
        self.techs: set[str] = set()
        self.resp_headers: dict = {}
        self.visited: set[str] = set()
        self.queued: set[str] = set()
        self.comments: list[str] = []
        self.subdomains: set[str] = set()
        self.dom_sinks: list[tuple[str, str, str]] = []
        self.interesting_names: set[str] = set()
        self.srcmap_sources: list[str] = []
        self.cors_issues: list[tuple[str, str]] = []
        self.bruteforce_results: list[tuple[str, int, int, str]] = []

        self._dirs: dict[str, Path] = {}
        self._dirs_ready = False

    # -- Logging --

    def _c(self, color: str, prefix: str, msg: str):
        line = f"{color}{prefix}{Style.RESET_ALL} {msg}"
        print(line)
        if self._log_fh:
            self._log_fh.write(RE_ANSI.sub("", line) + "\n")
            self._log_fh.flush()

    def log(self, msg):   self._c(Fore.CYAN,   "[*]", msg)
    def ok(self, msg):    self._c(Fore.GREEN,  "[+]", msg)
    def warn(self, msg):  self._c(Fore.YELLOW, "[!]", msg)
    def err(self, msg):   self._c(Fore.RED,    "[-]", msg)

    # -- Disk --

    def _ensure_dirs(self):
        if self._dirs_ready:
            return
        self._dirs = {
            "js": self.out / "01_js", "inline_js": self.out / "01_js" / "inline",
            "css": self.out / "02_css", "inline_css": self.out / "02_css" / "inline",
            "sourcemap": self.out / "01_js" / "sourcemaps",
            "extracted_src": self.out / "01_js" / "sourcemaps_extracted",
            "ext_js": self.out / "03_external" / "js",
            "ext_css": self.out / "03_external" / "css",
            "extra": self.out / "04_extra",
            "api_response": self.out / "05_api_responses",
            "bruteforce": self.out / "06_bruteforce",
            "wayback": self.out / "07_wayback",
            "git": self.out / "08_git",
        }
        for d in self._dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        self._dirs_ready = True

    def _resource_path(self, r: Resource) -> Path:
        fname = self._fname(r)
        if r.rtype == "html":
            return self.out / fname
        if r.external and r.rtype == "js":
            return self._dirs["ext_js"] / fname
        if r.external and r.rtype == "css":
            return self._dirs["ext_css"] / fname
        if r.rtype in self._dirs:
            return self._dirs[r.rtype] / fname
        return self._dirs["extra"] / fname

    def _persist(self, r: Resource):
        self._ensure_dirs()
        self._resource_path(r).write_text(r.content, encoding="utf-8")
        r.saved = True

    # -- Network --

    def _rate_limit(self):
        if self._stealth >= 1:
            self._rotate_headers()
            lo, hi = _STEALTH_CFG[min(self._stealth, 3)]["delay"]
            d = random.uniform(lo, hi) if lo != hi else lo
        elif self.delay > 0:
            d = self.delay
        else:
            return
        with self._rate_lock:
            wait = d - (time.time() - self._last_req)
            if wait > 0:
                time.sleep(wait)
            self._last_req = time.time()

    def _rotate_headers(self):
        if not self._ua_pool:
            return
        ua = random.choice(self._ua_pool)
        self.session.headers["User-Agent"] = ua
        self.session.headers["Accept-Language"] = random.choice(_ACCEPT_LANGS)
        for h in ("Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
                   "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
                   "Sec-Fetch-User", "Upgrade-Insecure-Requests"):
            self.session.headers.pop(h, None)
        m = re.search(r"Chrome/(\d+)", ua)
        if m and "Safari/" in ua:
            v = m.group(1)
            plat = ('"Windows"' if "Windows" in ua
                    else '"macOS"' if "Mac" in ua
                    else '"Android"' if "Android" in ua else '"Linux"')
            self.session.headers.update({
                "Sec-Ch-Ua": f'"Chromium";v="{v}", "Not_A Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?1" if "Mobile" in ua else "?0",
                "Sec-Ch-Ua-Platform": plat,
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            })

    def fetch(self, url: str) -> Optional[requests.Response]:
        if url in self.visited:
            return None
        self.visited.add(url)
        self._rate_limit()
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True, stream=True)
            size = int(r.headers.get("content-length", 0))
            if size > MAX_DOWNLOAD_SIZE:
                self.warn(f"Too large ({size // 1024 // 1024}MB), skip: {url[:80]}")
                r.close()
                return None
            r.raise_for_status()
            _ = r.text
            return r
        except requests.RequestException as e:
            self.err(f"{url[:90]}  ({e.__class__.__name__})")
            return None

    def _fetch_raw(self, url: str) -> Optional[requests.Response]:
        self._rate_limit()
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

    def resolve(self, href: str, base: str) -> str:
        if href.startswith(("data:", "javascript:", "mailto:", "blob:", "#")):
            return ""
        return urljoin(base, href)

    def is_same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == self.netloc

    # -- Parsing --

    def parse_html(self, html: str, base: str) -> list[Resource]:
        res: list[Resource] = []
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=True):
            url = self.resolve(tag["src"], base)
            if url:
                res.append(Resource(url, "js", base, external=not self.is_same_origin(url)))
        for i, tag in enumerate(soup.find_all("script", src=False)):
            body = tag.string or ""
            if body.strip():
                res.append(Resource(f"inline#{i}", "inline_js", base,
                                    content=body.strip(), filename=f"inline_{i}.js"))
        for tag in soup.find_all("link", rel="stylesheet"):
            href = tag.get("href", "")
            url = self.resolve(href, base)
            if url:
                res.append(Resource(url, "css", base, external=not self.is_same_origin(url)))
        for i, tag in enumerate(soup.find_all("style")):
            body = tag.string or ""
            if body.strip():
                res.append(Resource(f"inline_css#{i}", "inline_css", base,
                                    content=body.strip(), filename=f"inline_{i}.css"))
        for tag in soup.find_all("form"):
            action = tag.get("action", "")
            if action:
                full = self.resolve(action, base)
                if full:
                    self.endpoints.add(f"FORM {tag.get('method', 'GET').upper()} {full}")
            for inp in tag.find_all("input", attrs={"type": "hidden"}):
                name = inp.get("name", "")
                if name:
                    self.endpoints.add(f"HIDDEN_INPUT {name}={inp.get('value', '')}")
        for tag in soup.find_all("meta"):
            name = tag.get("name", tag.get("property", ""))
            content = tag.get("content", "")
            if name and content and any(k in name.lower() for k in ("api", "token", "key", "csrf", "config", "secret")):
                self.secrets.append((f"Meta[{name}]", content, base))
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = c.strip()
            if len(text) > 5:
                self.comments.append(text[:500])
        return res

    def extract_urls(self, text: str, source: str):
        for m in RE_URL.finditer(text):
            self.urls.add(m.group(0).rstrip(".,;:\"')}]"))
        for m in RE_PATH.finditer(text):
            self.endpoints.add(m.group(1))
        for pat in RE_ENDPOINT:
            for m in pat.finditer(text):
                self.endpoints.add(m.group(1))

    def extract_secrets(self, text: str, source: str):
        for name, pat in RE_SECRETS.items():
            for m in pat.finditer(text):
                val = m.group(1)
                if 4 < len(val) < 300:
                    self.secrets.append((name, val, source))

    def extract_configs(self, text: str, source: str):
        for m in RE_CONFIG.finditer(text):
            self.configs.append((m.group(0)[:2000], source))

    def extract_css_urls(self, text: str, base: str):
        for m in RE_CSS_URL.finditer(text):
            href = m.group(1)
            if not href.startswith("data:"):
                url = self.resolve(href, base)
                if url:
                    self.urls.add(url)

    def extract_subdomains(self, text: str):
        if not self.re_subdomain:
            return
        for m in self.re_subdomain.finditer(text):
            sub = m.group(1).lower()
            if sub != self.root_domain:
                self.subdomains.add(sub)

    def detect_dom_sinks(self, text: str, source: str):
        for sink_name, pat in DOM_SINKS.items():
            for m in pat.finditer(text):
                start, end = max(0, m.start() - 40), min(len(text), m.end() + 40)
                ctx = text[start:end].replace("\n", " ").strip()
                self.dom_sinks.append((sink_name, ctx[:150], source))

    def _deep_json(self, data, source: str, depth: int = 0):
        if depth > 10:
            return
        if isinstance(data, str) and len(data) > 4:
            for m in RE_URL.finditer(data):
                self.urls.add(m.group(0).rstrip(".,;:\"')}]"))
            for name, pat in RE_SECRETS.items():
                for m in pat.finditer(data):
                    val = m.group(1)
                    if 4 < len(val) < 300:
                        self.secrets.append((name, val, source))
            self.extract_subdomains(data)
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and any(h in k.lower() for h in JSON_KEY_HINTS):
                    self.endpoints.add(f"JSON[{k}]: {v}")
                self._deep_json(v, source, depth + 1)
        elif isinstance(data, list):
            for item in data:
                self._deep_json(item, source, depth + 1)

    def find_sourcemaps(self, text: str, base: str) -> list[Resource]:
        return [
            Resource(url, "sourcemap", base, external=not self.is_same_origin(url))
            for m in RE_SOURCEMAP.finditer(text)
            if (url := self.resolve(m.group(1), base))
        ]

    def find_js_refs(self, text: str, base: str) -> list[Resource]:
        out = []
        for pat in RE_JS_IMPORT:
            for m in pat.finditer(text):
                url = self.resolve(m.group(1), base)
                if url and url not in self.queued:
                    out.append(Resource(url, "js", base, external=not self.is_same_origin(url)))
        return out

    def detect_tech(self, html: str):
        low = html.lower()
        for tech, sigs in TECH_SIGNATURES.items():
            if any(re.search(s, low, re.I) for s in sigs):
                self.techs.add(tech)
        for hdr in ("Server", "X-Powered-By"):
            val = self.resp_headers.get(hdr, "")
            if val:
                self.techs.add(f"{hdr}: {val}")

    def analyze_sourcemap(self, content: str, source: str):
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return
        for s in data.get("sources", []):
            self.srcmap_sources.append(s)
        for n in data.get("names", []):
            if any(kw in n.lower() for kw in INTERESTING_KEYWORDS):
                self.interesting_names.add(n)
        sources = data.get("sources", [])
        for src_path, src_code in zip(sources, data.get("sourcesContent", [])):
            if not src_code or len(src_code) < 10:
                continue
            safe_name = re.sub(r"[^\w.\-]", "_", src_path.lstrip("./"))[:120]
            r = Resource(f"srcmap_extracted:{src_path}", "extracted_src", source,
                         content=src_code, filename=safe_name)
            self.resources.append(r)
            self._persist(r)
            if len(src_code) <= MAX_PARSE_SIZE:
                self.extract_urls(src_code, f"srcmap:{src_path}")
                self.extract_secrets(src_code, f"srcmap:{src_path}")
                self.extract_subdomains(src_code)
                self.detect_dom_sinks(src_code, f"srcmap:{src_path}")

    def _analyze(self, content: str, url: str, rtype: str):
        if len(content) > MAX_PARSE_SIZE:
            self.warn(f"Too large for analysis ({len(content) // 1024}KB): {url[:80]}")
            return
        self.extract_urls(content, url)
        self.extract_secrets(content, url)
        self.extract_configs(content, url)
        self.extract_subdomains(content)
        if rtype in ("css", "inline_css"):
            self.extract_css_urls(content, url)
        if rtype in ("js", "inline_js"):
            self.detect_dom_sinks(content, url)
        if rtype == "sourcemap":
            self.analyze_sourcemap(content, url)

    # -- Download --

    def _dl(self, r: Resource) -> bool:
        if r.content:
            return True
        resp = self.fetch(r.url)
        if resp:
            r.content = resp.text
            return True
        return False

    def _fname(self, r: Resource) -> str:
        if r.filename:
            return r.filename
        p = urlparse(r.url)
        name = (p.path.strip("/") or "index").replace("/", "_")
        if p.query:
            name += "_" + hashlib.md5(p.query.encode()).hexdigest()[:8]
        return name

    def _url_to_fname(self, url: str) -> str:
        p = urlparse(url)
        name = (p.path.strip("/") or "index").replace("/", "_")
        if p.query:
            name += "_" + hashlib.md5(p.query.encode()).hexdigest()[:8]
        if not name.endswith((".json", ".xml", ".txt")):
            name += ".txt"
        return name

    # -- Features --

    def _fetch_extras(self):
        self.log("Fetching robots.txt, sitemap.xml, security.txt ...")
        for fname in EXTRA_FILES:
            url = f"{self.base_origin}/{fname}"
            resp = self.fetch(url)
            if resp and resp.status_code == 200 and resp.text.strip():
                r = Resource(url, "extra", self.base_url,
                             content=resp.text, filename=fname.replace("/", "_"))
                self.resources.append(r)
                self._persist(r)
                self.ok(f"Found {fname}")

    def _fetch_api_endpoints(self):
        api_kw = (".json", "/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/_next/data/")
        candidates: set[str] = set()
        for url in self.urls:
            if any(k in url.lower() for k in api_kw):
                candidates.add(url)
        for ep in self.endpoints:
            if ep.startswith(("http://", "https://")) and any(k in ep.lower() for k in api_kw):
                candidates.add(ep)
            elif ep.startswith("/") and any(k in ep.lower() for k in api_kw):
                candidates.add(f"{self.base_origin}{ep}")
        candidates -= self.visited
        if not candidates:
            return
        self.log(f"Probing {len(candidates)} API endpoints ...")
        for url in list(candidates)[:50]:
            resp = self.fetch(url)
            if not resp:
                continue
            cors = resp.headers.get("access-control-allow-origin", "")
            if cors:
                self.cors_issues.append((url, cors))
            r = Resource(url, "api_response", self.base_url,
                         content=resp.text[:50000], filename=self._url_to_fname(url))
            self.resources.append(r)
            self._persist(r)
            self.ok(f"API [{resp.status_code}] {url[:80]}")
            ct = resp.headers.get("content-type", "")
            if "json" in ct:
                try:
                    self._deep_json(json.loads(resp.text), url)
                except (json.JSONDecodeError, ValueError):
                    pass
            if len(resp.text) <= MAX_PARSE_SIZE:
                self.extract_urls(resp.text, url)
                self.extract_secrets(resp.text, url)
                self.extract_subdomains(resp.text)

    def _probe_path(self, path: str) -> Optional[tuple[str, int, int, str, str]]:
        url = f"{self.base_origin}{path}"
        r = self._fetch_raw(url)
        if not r or r.status_code == 404:
            return None
        redirect = ""
        if r.status_code in (301, 302, 303, 307, 308):
            redirect = r.headers.get("location", "")
        body = r.text[:5000] if r.status_code == 200 else ""
        return (url, r.status_code, len(r.content), body, redirect)

    def _detect_waf(self):
        self.log("WAF detection ...")
        test_url = f"{self.base_origin}/?id=%27%20OR%201%3D1--&q=%3Cscript%3Ealert(1)%3C/script%3E"
        try:
            r = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return
        detected: list[str] = []
        combined = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower() + " "
        combined += r.text[:5000].lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(s in combined for s in sigs):
                detected.append(waf_name)
        if r.status_code in (403, 406, 429, 503):
            self.warn(f"WAF likely active! Test payload returned {r.status_code}")
            if detected:
                self.warn(f"WAF signature: {', '.join(detected)}")
            else:
                self.warn("WAF type: unknown")
            self.warn("Bruteforce may trigger blocks. Consider --delay")
        elif detected:
            self.warn(f"WAF signature found: {', '.join(detected)} (but test passed)")

    def _bruteforce_run(self):
        self.log(f"Bruteforce: {len(BRUTEFORCE_PATHS)} paths, {self.threads} threads ...")
        found = 0
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe_path, p): p for p in BRUTEFORCE_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if not result:
                    continue
                url, status, size, body, redirect = result
                self.bruteforce_results.append((url, status, size, redirect))
                color = Fore.GREEN if status == 200 else Fore.YELLOW
                suffix = f" → {redirect}" if redirect else ""
                self._c(color, "[B]", f"[{status}] {size:>6}B  {url}{suffix}")
                found += 1
                if body:
                    r = Resource(url, "bruteforce", self.base_url, content=body,
                                 filename="bf_" + url.split("/", 3)[-1].replace("/", "_").strip("_"))
                    self.resources.append(r)
                    self._persist(r)
        self.ok(f"Bruteforce done: {found} hits")

    def _git_dump(self):
        git_200 = any("/.git" in u and st == 200 for u, st, _, _ in self.bruteforce_results)
        if not git_200:
            return
        self.log("Git repository detected! Dumping ...")
        for gf in GIT_FILES:
            url = f"{self.base_origin}/.git/{gf}"
            resp = self._fetch_raw(url)
            if not resp or resp.status_code != 200 or not resp.text.strip():
                continue
            r = Resource(url, "git", self.base_url,
                         content=resp.text, filename=f"git_{gf.replace('/', '_')}")
            self.resources.append(r)
            self._persist(r)
            self.ok(f"Git: /.git/{gf}")
            if gf == "config":
                self.extract_urls(resp.text, f"git:config")
                self.extract_secrets(resp.text, f"git:config")
            elif "logs" in gf:
                for m in re.finditer(r"<([^>]+@[^>]+)>", resp.text):
                    self.secrets.append(("Git Author Email", m.group(1), f"git:{gf}"))

    def _fetch_wayback(self):
        self.log("Querying Wayback Machine CDX API ...")
        hostname = self.parsed.hostname
        cdx = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={hostname}/*&output=json"
            f"&fl=original,timestamp,statuscode,mimetype"
            f"&filter=statuscode:200&collapse=urlkey&limit=200"
        )
        try:
            resp = requests.get(cdx, timeout=30)
            resp.raise_for_status()
            rows = resp.json()
        except Exception as e:
            self.err(f"Wayback CDX: {e}")
            return
        if len(rows) < 2:
            self.log("No Wayback results")
            return
        keys = rows[0]
        entries = [dict(zip(keys, r)) for r in rows[1:]]
        self.ok(f"Wayback: {len(entries)} archived URLs")

        all_urls = sorted({e["original"] for e in entries})
        for u in all_urls:
            self.urls.add(u)
        r_urls = Resource("wayback:urls", "wayback", self.base_url,
                          content="\n".join(all_urls), filename="wayback_urls.txt")
        self.resources.append(r_urls)
        self._persist(r_urls)

        js_entries = [e for e in entries if "javascript" in e.get("mimetype", "").lower()]
        self.log(f"Downloading {min(len(js_entries), 30)} archived JS files ...")
        for entry in js_entries[:30]:
            wb_url = f"https://web.archive.org/web/{entry['timestamp']}id_/{entry['original']}"
            try:
                dl = requests.get(wb_url, timeout=self.timeout)
                if dl.status_code != 200:
                    continue
            except Exception:
                continue
            safe = "wb_" + re.sub(r"[^\w.\-]", "_", urlparse(entry["original"]).path.strip("/"))[:100]
            r = Resource(entry["original"], "wayback", wb_url,
                         content=dl.text, filename=safe)
            self.resources.append(r)
            self._persist(r)
            self.ok(f"WB: {entry['original'][:70]}")
            if len(dl.text) <= MAX_PARSE_SIZE:
                self._analyze(dl.text, f"wayback:{entry['original']}", "js")

    # -- Run --

    def run(self):
        colorama_init()
        try:
            self._run()
        except KeyboardInterrupt:
            self.warn("\nInterrupted! Saving collected data ...")
            self._save()
        finally:
            if self._log_fh:
                self._log_fh.close()

    def _run(self):
        print()
        self.log(f"Target : {self.base_url}")
        self.log(f"Output : {self.out}")
        self.log(f"Depth  : {self.depth}")
        if self._stealth >= 1:
            names = {1: "LIGHT", 2: "MEDIUM", 3: "HEAVY"}
            scfg = _STEALTH_CFG[min(self._stealth, 3)]
            lo, hi = scfg["delay"]
            ds = f"{lo}s" if lo == hi else f"{lo}-{hi}s"
            self.log(f"Mode   : STEALTH {names.get(self._stealth, 'HEAVY')} "
                     f"({scfg['threads']}t, {ds}, {scfg['ua_count']} UAs)")
        if self.is_ip:
            self.log("Mode   : IP target (subdomain search disabled)")
        if self.delay > 0 and self._stealth < 1:
            self.log(f"Delay  : {self.delay}s between requests")
        print()

        self._ensure_dirs()

        resp = self.fetch(self.base_url)
        if not resp:
            self.err("Cannot fetch target. Aborting.")
            sys.exit(1)

        self.resp_headers = dict(resp.headers)
        html = resp.text
        main = Resource(self.base_url, "html", "", content=html, filename="00_main.html")
        self.resources.append(main)
        self._persist(main)

        self.detect_tech(html)
        found = self.parse_html(html, self.base_url)
        self._analyze(html, self.base_url, "html")

        queue: list[tuple[Resource, int]] = []
        for r in found:
            self.queued.add(r.url)
            queue.append((r, 0))

        while queue:
            r, lvl = queue.pop(0)
            if r.url in self.visited and not r.content:
                continue
            if not self._dl(r):
                continue
            self.resources.append(r)
            self._persist(r)
            label = "EXT " if r.external else ""
            self.ok(f"{'  ' * lvl}{label}{r.rtype:<10} {r.url[:90]}")
            self._analyze(r.content, r.url, r.rtype)
            if r.rtype in ("js", "inline_js", "css"):
                for sm in self.find_sourcemaps(r.content, r.url):
                    if sm.url not in self.queued:
                        self.queued.add(sm.url)
                        queue.append((sm, lvl))
            if lvl < self.depth and r.rtype in ("js", "inline_js"):
                for sub in self.find_js_refs(r.content, r.url):
                    if sub.url not in self.queued:
                        self.queued.add(sub.url)
                        queue.append((sub, lvl + 1))

        if self.fetch_extras:
            self._fetch_extras()
        self._fetch_api_endpoints()
        if self.bruteforce:
            print()
            self._detect_waf()
            self._bruteforce_run()
            self._git_dump()
        if self.wayback:
            print()
            self._fetch_wayback()
        print()
        self._save()

    # -- Save --

    def _save(self):
        self._ensure_dirs()
        if self.onefile:
            self._save_onefile()
        for r in self.resources:
            if not r.saved:
                self._persist(r)
        self._save_report()
        if self.json_report:
            self._save_json_report()
        if self.html_report:
            self._save_html_report()
        print()
        self.ok(f"Done! Output → {self.out}/")
        stats = [
            ("JS files",          sum(1 for r in self.resources if r.rtype == "js")),
            ("Inline scripts",    sum(1 for r in self.resources if r.rtype == "inline_js")),
            ("CSS files",         sum(1 for r in self.resources if r.rtype == "css")),
            ("Source maps",       sum(1 for r in self.resources if r.rtype == "sourcemap")),
            ("Extracted sources", sum(1 for r in self.resources if r.rtype == "extracted_src")),
            ("API responses",     sum(1 for r in self.resources if r.rtype == "api_response")),
            ("Bruteforce hits",   len(self.bruteforce_results)),
            ("Wayback files",     sum(1 for r in self.resources if r.rtype == "wayback")),
            ("Git files",         sum(1 for r in self.resources if r.rtype == "git")),
            ("URLs found",        len(self.urls)),
            ("Endpoints",         len(self.endpoints)),
            ("Potential secrets",  len(self.secrets)),
            ("Config objects",    len(self.configs)),
            ("DOM sinks",         len(self.dom_sinks)),
            ("Subdomains",        len(self.subdomains)),
            ("CORS issues",       len(self.cors_issues)),
            ("Technologies",      len(self.techs)),
            ("Sourcemap names",   len(self.interesting_names)),
        ]
        for name, count in stats:
            if count:
                c = Fore.RED if any(k in name.lower() for k in ("secret", "cors", "sink")) else Fore.GREEN
                print(f"  {c}{name}: {count}{Style.RESET_ALL}")

    def _save_onefile(self):
        sep = "=" * 80
        parts = []
        for r in self.resources:
            parts.append(f"\n{sep}")
            parts.append(f"  URL  : {r.url}")
            parts.append(f"  TYPE : {r.rtype}{'  [EXTERNAL]' if r.external else ''}")
            if r.source:
                parts.append(f"  FROM : {r.source}")
            parts.append(f"{sep}\n")
            if r.saved and not r.content:
                p = self._resource_path(r)
                parts.append(p.read_text(encoding="utf-8") if p.exists() else "")
            else:
                parts.append(r.content)
        (self.out / "full_dump.txt").write_text("\n".join(parts), encoding="utf-8")
        self.ok("Saved full_dump.txt")

    def _save_report(self):
        w: list[str] = []
        w.append(f"# RECON REPORT: {self.base_url}")
        w.append(f"# Date: {datetime.now():%Y-%m-%d %H:%M:%S}")
        w.append(f"# Target type: {'IP' if self.is_ip else 'Domain'}\n")
        if self.resp_headers:
            w.append("## RESPONSE HEADERS\n" + "-" * 60)
            for k, v in self.resp_headers.items():
                w.append(f"  {k}: {v}")
            w.append("")
            missing = [h for h in SECURITY_HEADERS if h.lower() not in {k.lower() for k in self.resp_headers}]
            if missing:
                w.append("## MISSING SECURITY HEADERS\n" + "-" * 60)
                for h in missing:
                    w.append(f"  [!] {h}")
                w.append("")
        if self.techs:
            w.append("## DETECTED TECHNOLOGIES\n" + "-" * 60)
            for t in sorted(self.techs):
                w.append(f"  - {t}")
            w.append("")
        if self.secrets:
            w.append("## POTENTIAL SECRETS / SENSITIVE DATA\n" + "-" * 60)
            seen = set()
            for stype, val, src in self.secrets:
                key = f"{stype}:{val}"
                if key not in seen:
                    seen.add(key)
                    w.append(f"  [{stype}] {val}")
                    w.append(f"    Source: {src}")
            w.append("")
        if self.cors_issues:
            w.append("## CORS ISSUES\n" + "-" * 60)
            for url, origin in self.cors_issues:
                w.append(f"  {url}  →  ACAO: {origin}")
            w.append("")
        if self.dom_sinks:
            w.append("## DOM SINKS (XSS vectors)\n" + "-" * 60)
            seen = set()
            for sink, ctx, src in self.dom_sinks:
                key = f"{sink}:{ctx}"
                if key not in seen:
                    seen.add(key)
                    w.append(f"  [{sink}]  {ctx}")
                    w.append(f"    Source: {src}")
            w.append("")
        if self.configs:
            w.append("## CONFIGURATION OBJECTS\n" + "-" * 60)
            for raw, src in self.configs:
                w.append(f"  Source: {src}")
                w.append(f"  {raw[:1500]}\n")
        if self.interesting_names:
            w.append("## INTERESTING SOURCEMAP NAMES\n" + "-" * 60)
            for n in sorted(self.interesting_names):
                w.append(f"  {n}")
            w.append("")
        if self.srcmap_sources:
            w.append("## SOURCEMAP FILE PATHS\n" + "-" * 60)
            for s in sorted(set(self.srcmap_sources)):
                w.append(f"  {s}")
            w.append("")
        if self.subdomains:
            w.append("## DISCOVERED SUBDOMAINS\n" + "-" * 60)
            for s in sorted(self.subdomains):
                w.append(f"  {s}")
            w.append("")
        if self.endpoints:
            w.append("## ENDPOINTS / PATHS\n" + "-" * 60)
            for e in sorted(self.endpoints):
                w.append(f"  {e}")
            w.append("")
        if self.bruteforce_results:
            w.append("## BRUTEFORCE RESULTS\n" + "-" * 60)
            for url, status, size, redir in sorted(self.bruteforce_results, key=lambda x: x[1]):
                suffix = f" → {redir}" if redir else ""
                w.append(f"  [{status}] {size:>6}B  {url}{suffix}")
            w.append("")
        if self.urls:
            w.append("## ALL URLS\n" + "-" * 60)
            for u in sorted(self.urls):
                w.append(f"  {u}")
            w.append("")
        if self.comments:
            w.append("## HTML COMMENTS\n" + "-" * 60)
            for c in self.comments:
                w.append(f"  {c}")
            w.append("")
        w.append("## RESOURCE INDEX\n" + "-" * 60)
        for r in self.resources:
            flag = "EXT" if r.external else "INT"
            w.append(f"  [{flag}] [{r.rtype:<14}] {r.url}")
        w.append("")
        (self.out / "report.txt").write_text("\n".join(w), encoding="utf-8")
        self.ok("Saved report.txt")

    def _save_json_report(self):
        seen = set()
        secrets = []
        for t, v, s in self.secrets:
            key = f"{t}:{v}"
            if key not in seen:
                seen.add(key)
                secrets.append({"type": t, "value": v, "source": s})
        seen_sinks = set()
        sinks = []
        for t, c, s in self.dom_sinks:
            key = f"{t}:{c}"
            if key not in seen_sinks:
                seen_sinks.add(key)
                sinks.append({"type": t, "context": c, "source": s})
        report = {
            "target": self.base_url,
            "target_type": "ip" if self.is_ip else "domain",
            "date": datetime.now().isoformat(),
            "response_headers": self.resp_headers,
            "missing_security_headers": [
                h for h in SECURITY_HEADERS
                if h.lower() not in {k.lower() for k in self.resp_headers}
            ],
            "technologies": sorted(self.techs),
            "secrets": secrets,
            "cors_issues": [{"url": u, "origin": o} for u, o in self.cors_issues],
            "dom_sinks": sinks,
            "configs": [{"content": c, "source": s} for c, s in self.configs],
            "interesting_names": sorted(self.interesting_names),
            "sourcemap_paths": sorted(set(self.srcmap_sources)),
            "subdomains": sorted(self.subdomains),
            "endpoints": sorted(self.endpoints),
            "bruteforce": [{"url": u, "status": st, "size": sz, "redirect": rd}
                           for u, st, sz, rd in self.bruteforce_results],
            "urls": sorted(self.urls),
            "comments": self.comments,
            "resources": [{"url": r.url, "type": r.rtype, "external": r.external}
                          for r in self.resources],
        }
        (self.out / "report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        self.ok("Saved report.json")

    def _save_html_report(self):
        from html import escape as esc

        tc: dict[str, int] = {}
        for r in self.resources:
            tc[r.rtype] = tc.get(r.rtype, 0) + 1
        total = sum(tc.values()) or 1
        mx = max(tc.values()) if tc else 1

        seen_s: set[str] = set()
        ds: list[tuple[str, str, str]] = []
        for t, v, s in self.secrets:
            k = f"{t}:{v}"
            if k not in seen_s:
                seen_s.add(k)
                ds.append((t, v, s))
        seen_k: set[str] = set()
        dsk: list[tuple[str, str, str]] = []
        for t, c, s in self.dom_sinks:
            k = f"{t}:{c}"
            if k not in seen_k:
                seen_k.add(k)
                dsk.append((t, c, s))
        miss = [h for h in SECURITY_HEADERS
                if h.lower() not in {k.lower() for k in self.resp_headers}]
        CC = _CHART_COLORS

        # --- SVG donut ---
        circ = 251.33
        off, arcs = 0.0, ""
        for rt, cnt in sorted(tc.items(), key=lambda x: -x[1]):
            d = (cnt / total) * circ
            arcs += (f'<circle cx="50" cy="50" r="40" fill="none" '
                     f'stroke="{CC.get(rt, "#6e7681")}" stroke-width="15" '
                     f'stroke-dasharray="{d:.1f} {circ}" '
                     f'stroke-dashoffset="{-off:.1f}"/>')
            off += d
        donut = (f'<svg viewBox="0 0 100 100" width="180" height="180">'
                 f'<g transform="rotate(-90 50 50)">{arcs}</g>'
                 f'<text x="50" y="54" text-anchor="middle" fill="#c9d1d9" '
                 f'font-size="16" font-weight="700">{total}</text></svg>')

        # --- bars ---
        bars = "\n".join(
            f'<div class="br"><span class="bl">{esc(rt)} ({cnt})</span>'
            f'<div class="bt"><div class="b" style="width:{cnt / mx * 100:.0f}%;'
            f'background:{CC.get(rt, "#6e7681")}"></div></div></div>'
            for rt, cnt in sorted(tc.items(), key=lambda x: -x[1]))

        # --- stat cards ---
        cd = [
            (sum(1 for r in self.resources if r.rtype == "js"), "JS", "#f0883e"),
            (sum(1 for r in self.resources
                 if r.rtype in ("inline_js", "inline_css")), "Inline", "#d29922"),
            (len(self.endpoints), "Endpoints", "#58a6ff"),
            (len(ds), "Secrets", "#da3633"),
            (len(self.urls), "URLs", "#3fb950"),
            (len(dsk), "DOM Sinks", "#a371f7"),
            (len(self.subdomains), "Subdomains", "#79c0ff"),
            (len(self.bruteforce_results), "BF Hits", "#f0883e"),
        ]
        cards = "".join(
            f'<div class="cd"><div class="cv" style="color:{c}">{v}</div>'
            f'<div class="cl">{la}</div></div>'
            for v, la, c in cd if v)

        # --- sections ---
        S: list[str] = []
        S.append(f'<section id="sum"><h2>Summary</h2>'
                 f'<div class="cards">{cards}</div></section>')
        if tc:
            S.append(f'<section id="res"><h2>Resource Distribution</h2>'
                     f'<div class="chart"><div>{donut}</div>'
                     f'<div class="bars">{bars}</div></div></section>')
        if self.techs:
            tags = "".join(f'<span class="tg g">{esc(t)}</span>'
                           for t in sorted(self.techs))
            S.append(f'<section><h2>Technologies</h2>'
                     f'<div class="tags">{tags}</div></section>')
        if miss:
            tags = "".join(f'<span class="tg r">{esc(m)}</span>' for m in miss)
            S.append(f'<section><h2>Missing Security Headers</h2>'
                     f'<div class="tags">{tags}</div></section>')
        if ds:
            rows = "".join(
                f'<tr><td>{esc(t)}</td><td class="sv">{esc(v)}</td>'
                f'<td class="sr">{esc(s)}</td></tr>' for t, v, s in ds)
            S.append(
                f'<section id="sec"><h2>Secrets ({len(ds)})</h2><div class="tw">'
                f'<table><thead><tr><th>Type</th><th>Value</th><th>Source</th>'
                f'</tr></thead><tbody>{rows}</tbody></table></div></section>')
        if self.cors_issues:
            rows = "".join(
                f'<tr><td>{esc(u)}</td><td class="sv">{esc(o)}</td></tr>'
                for u, o in self.cors_issues)
            S.append(
                f'<section><h2>CORS Issues</h2><div class="tw">'
                f'<table><thead><tr><th>URL</th><th>ACAO</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div></section>')
        if dsk:
            rows = "".join(
                f'<tr><td>{esc(t)}</td><td><code>{esc(c)}</code></td>'
                f'<td class="sr">{esc(s)}</td></tr>' for t, c, s in dsk)
            S.append(
                f'<section><h2>DOM Sinks ({len(dsk)})</h2><div class="tw">'
                f'<table><thead><tr><th>Type</th><th>Context</th><th>Source</th>'
                f'</tr></thead><tbody>{rows}</tbody></table></div></section>')
        if self.endpoints:
            rows = "".join(
                f'<tr><td>{i}</td><td><code>{esc(e)}</code></td></tr>'
                for i, e in enumerate(sorted(self.endpoints), 1))
            S.append(
                f'<section id="ep"><h2>Endpoints ({len(self.endpoints)})</h2>'
                f'<div class="tw"><table><thead><tr><th>#</th><th>Endpoint</th>'
                f'</tr></thead><tbody>{rows}</tbody></table></div></section>')
        if self.bruteforce_results:
            rows = "".join(
                f'<tr class="{"ok" if st == 200 else "wn"}">'
                f'<td>{st}</td><td>{sz}</td><td>{esc(u)}</td>'
                f'<td>{esc(rd)}</td></tr>'
                for u, st, sz, rd in sorted(self.bruteforce_results,
                                            key=lambda x: x[1]))
            S.append(
                f'<section id="bf"><h2>Bruteforce ({len(self.bruteforce_results)})'
                f'</h2><div class="tw"><table><thead><tr><th>Status</th>'
                f'<th>Size</th><th>URL</th><th>Redirect</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div></section>')
        if self.urls:
            pre = "\n".join(esc(u) for u in sorted(self.urls))
            S.append(
                f'<section id="urls"><details><summary>'
                f'<h2 style="display:inline">All URLs ({len(self.urls)})</h2>'
                f'</summary><pre>{pre}</pre></details></section>')
        if self.comments:
            pre = "\n".join(esc(c) for c in self.comments)
            S.append(
                f'<section><details><summary>'
                f'<h2 style="display:inline">HTML Comments ({len(self.comments)})'
                f'</h2></summary><pre>{pre}</pre></details></section>')

        # --- nav ---
        nav_items: list[tuple[str, str]] = [("sum", "Summary"), ("res", "Resources")]
        if ds:
            nav_items.append(("sec", f"Secrets ({len(ds)})"))
        if self.endpoints:
            nav_items.append(("ep", f"Endpoints ({len(self.endpoints)})"))
        if self.bruteforce_results:
            nav_items.append(("bf", "Bruteforce"))
        if self.urls:
            nav_items.append(("urls", f"URLs ({len(self.urls)})"))
        nav = "".join(f'<a href="#{a}">{la}</a>' for a, la in nav_items)

        html = (
            f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Report: {esc(self.base_url)}</title>'
            f'<style>{_HTML_CSS}</style></head><body>'
            f'<header><h1>Page Dumper Report</h1>'
            f'<p class="m">{esc(self.base_url)} &bull; '
            f'{datetime.now():%Y-%m-%d %H:%M:%S} &bull; '
            f'{"IP" if self.is_ip else "Domain"}</p></header>'
            f'<nav>{nav}</nav>{"".join(S)}</body></html>'
        )
        (self.out / "report.html").write_text(html, encoding="utf-8")
        self.ok("Saved report.html")


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="dumper",
        description="Page Dumper — grab & analyze web page sources for recon / bug bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s https://example.com
  %(prog)s https://example.com -o -d 2 -b -t 20 --json-report
  %(prog)s http://10.0.0.1:8080 --host-header target.local -k
  %(prog)s --config scan.json
  %(prog)s https://target.com --wayback --log scan.log""",
    )
    p.add_argument("url", nargs="?", default=None,            help="target URL")
    p.add_argument("-c", "--config",     type=str,             help="JSON config file")
    p.add_argument("-o", "--onefile",    action="store_true",  help="single full_dump.txt")
    p.add_argument("-d", "--depth",      type=int, default=None, help="JS recursion depth (default: 1)")
    p.add_argument("-b", "--bruteforce", action="store_true",  help="directory bruteforce")
    p.add_argument("-t", "--threads",    type=int, default=None, help="bruteforce threads (default: 10)")
    p.add_argument("--output",          type=str, default=None, help="output directory")
    p.add_argument("--timeout",         type=int, default=None, help="request timeout sec (default: 15)")
    p.add_argument("--no-extras",       action="store_true",   help="skip robots.txt etc.")
    p.add_argument("-A", "--user-agent", type=str, default=None, help="custom User-Agent")
    p.add_argument("-H", "--header",     action="append", default=[], help="custom header (Key: Value)")
    p.add_argument("--cookie",          type=str, default=None, help="cookies (k=v; k2=v2)")
    p.add_argument("--proxy",           type=str, default=None, help="HTTP proxy")
    p.add_argument("-k", "--insecure",   action="store_true",  help="skip SSL verify")
    p.add_argument("--host-header",     type=str, default=None, help="override Host header")
    p.add_argument("--json-report",     action="store_true",   help="save report.json")
    p.add_argument("--html-report",     action="store_true",   help="save report.html with charts")
    p.add_argument("--stealth",         type=int, nargs="?", const=2, default=None,
                                        metavar="LVL",
                                        help="stealth: 1=light 2=medium(default) 3=heavy")
    p.add_argument("--delay",           type=float, default=None, help="delay between requests in sec")
    p.add_argument("--wayback",         action="store_true",   help="fetch from Wayback Machine")
    p.add_argument("--log",             type=str, default=None, help="log output to file", metavar="FILE")
    args = p.parse_args()

    cfg = json.loads(Path(args.config).read_text()) if args.config else {}
    url = args.url or cfg.get("url")
    if not url:
        p.error("target URL required (positional arg or 'url' in config)")

    def opt(cli, key, default=None):
        return cli if cli is not None else cfg.get(key, default)

    headers = dict(cfg.get("headers", {}))
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    PageDumper(
        url=url,
        output=opt(args.output, "output"),
        depth=opt(args.depth, "depth", 1),
        onefile=args.onefile or cfg.get("onefile", False),
        timeout=opt(args.timeout, "timeout", 15),
        user_agent=opt(args.user_agent, "user_agent"),
        fetch_extras=not (args.no_extras or cfg.get("no_extras", False)),
        headers=headers or None,
        cookies=opt(args.cookie, "cookies"),
        proxy=opt(args.proxy, "proxy"),
        insecure=args.insecure or cfg.get("insecure", False),
        bruteforce=args.bruteforce or cfg.get("bruteforce", False),
        threads=opt(args.threads, "threads", 10),
        host_header=opt(args.host_header, "host_header"),
        json_report=args.json_report or cfg.get("json_report", False),
        html_report=args.html_report or cfg.get("html_report", False),
        wayback=args.wayback or cfg.get("wayback", False),
        delay=opt(args.delay, "delay", 0),
        stealth=(args.stealth if args.stealth is not None
                 else (2 if cfg.get("stealth") is True
                       else int(cfg.get("stealth", 0)))),
        log_path=args.log or cfg.get("log"),
    ).run()


if __name__ == "__main__":
    main()
