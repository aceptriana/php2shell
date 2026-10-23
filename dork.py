#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
#     "tqdm>=4.64.0",
# ]
# ///
"""
dork.py — Auto-dorking companion for php2shell-scanner
          CVE-2026-109618 / CVE-2026-109619

Discovers PHP hosts running unpatched versions via multiple OSINT search
backends, then writes a host list ready for `scanner.py -l`.

Credentials are loaded from config.py (config file → env vars → CLI flag).
Run `python config.py --set shodan_api_key=xxx` to store keys persistently.

Backends
--------
  Free / scrape (no key needed):
    --google      Google web search
    --ddg         DuckDuckGo HTML search
    --yahoo       Yahoo web search

  API (key required — configure with config.py):
    --bing        Bing Web Search API
    --shodan      Shodan Search API
    --censys      Censys Hosts v2 API
    --fofa        FOFA Search API
    --zoomeye     ZoomEye Host Search API

Quick start
-----------
  python config.py --set shodan_api_key=sk-xxxxx
  python dork.py --shodan -o targets.txt
  python scanner.py -l targets.txt -t 20 -o results.json

  python dork.py --google --ddg --yahoo -o targets.txt -n 50
  python dork.py --all -o targets.txt
  python dork.py --list-dorks
"""

import argparse
import base64
import json
import os
import re
import ssl as _ssl
import sys
import time
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry  # type: ignore[import-untyped]

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from tqdm import tqdm  # noqa: F401

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# Load config (works even without config.py present)
try:
    from config import load_config as _load_config, SETTING_DEFAULTS as _SETTING_DEFAULTS
    HAS_CONFIG = True
except ImportError:
    HAS_CONFIG = False

    def _load_config(*_a, **_kw):  # type: ignore[misc]
        return type("_Cfg", (), {
            "get":     lambda self, k, d="": os.environ.get(k.upper(), d),
            "setting": lambda self, k, d=None: d,
        })()

# ---------------------------------------------------------------------------
# Vulnerability metadata  (mirrors scanner.py)
# ---------------------------------------------------------------------------

CVES = "CVE-2026-109618 / CVE-2026-109619"

# (major, minor) → first patched patch number  (anything below is vulnerable)
FIXED_VERSIONS: Dict = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

VULN_MINORS: List[str] = sorted(
    f"{maj}.{min_}" for (maj, min_) in FIXED_VERSIONS
)

# ---------------------------------------------------------------------------
# Dork catalogs
# ---------------------------------------------------------------------------

# Google / DuckDuckGo / Yahoo  (content/title-based)
GOOGLE_DORKS: List[str] = [
    'intitle:"phpinfo()" "PHP Version 8.2"',
    'intitle:"phpinfo()" "PHP Version 8.3"',
    'intitle:"phpinfo()" "PHP Version 8.4"',
    'intitle:"phpinfo()" "PHP Version 8.5"',
    'inurl:"/phpinfo.php" "PHP Version 8"',
    'inurl:"/info.php" "PHP Version 8"',
    'inurl:"/test.php" "PHP Version 8"',
    'intitle:"phpMyAdmin" inurl:"/phpmyadmin"',
    'intitle:"Welcome to phpMyAdmin"',
    '"Fatal error" "PHP 8.2"',
    '"Fatal error" "PHP 8.3"',
    '"Fatal error" "PHP 8.4"',
    '"Powered by PHP/8.2"',
    '"Powered by PHP/8.3"',
    '"Powered by PHP/8.4"',
]

DDG_DORKS: List[str] = [
    'intitle:"phpinfo()" "PHP Version 8.2"',
    'intitle:"phpinfo()" "PHP Version 8.3"',
    'intitle:"phpinfo()" "PHP Version 8.4"',
    'intitle:"phpinfo()" "PHP Version 8.5"',
    'intitle:"phpMyAdmin"',
    'inurl:phpinfo.php "PHP 8"',
    '"Fatal error" "PHP/8.2"',
    '"Fatal error" "PHP/8.3"',
    '"Fatal error" "PHP/8.4"',
    '"X-Powered-By: PHP/8.2"',
    '"X-Powered-By: PHP/8.3"',
    '"X-Powered-By: PHP/8.4"',
]

YAHOO_DORKS: List[str] = [
    'intitle:"phpinfo()" "PHP Version 8.2"',
    'intitle:"phpinfo()" "PHP Version 8.3"',
    'intitle:"phpinfo()" "PHP Version 8.4"',
    'intitle:"phpinfo()" "PHP Version 8.5"',
    'intitle:"phpMyAdmin" "php 8"',
    'inurl:"/phpinfo.php" PHP',
    '"Fatal error" "PHP 8.2"',
    '"Fatal error" "PHP 8.3"',
    '"Fatal error" "PHP 8.4"',
]

# Bing  (separate index from Google, same operator support)
BING_DORKS: List[str] = [
    'intitle:"phpinfo()" "PHP Version 8.2"',
    'intitle:"phpinfo()" "PHP Version 8.3"',
    'intitle:"phpinfo()" "PHP Version 8.4"',
    'intitle:"phpinfo()" "PHP Version 8.5"',
    'intitle:"phpMyAdmin" "php 8"',
    'inurl:phpinfo.php "PHP 8"',
    '"Allowed memory size" "PHP 8.2" "Fatal error"',
    '"Allowed memory size" "PHP 8.3" "Fatal error"',
    '"Allowed memory size" "PHP 8.4" "Fatal error"',
]

# Shodan  (header-indexed, very precise)
SHODAN_DORKS: List[str] = [
    *[f'"X-Powered-By: PHP/{minor}"' for minor in VULN_MINORS],
    *[f'http.component:"PHP" http.component.version:"{minor}"' for minor in VULN_MINORS],
    'title:"phpMyAdmin" http.component:"PHP"',
    '"X-Powered-By: PHP/8" product:"nginx"',
    '"X-Powered-By: PHP/8" product:"Apache httpd"',
    'title:"PHP-FPM status page"',
]

# Censys  (internet-wide TLS/HTTP scan data)
CENSYS_QUERIES: List[str] = [
    *[f'services.http.response.headers.x-powered-by: "PHP/{minor}"'
      for minor in VULN_MINORS],
    'services.http.response.html_title: "phpMyAdmin"',
    ('services.http.response.body: "phpMyAdmin" and '
     'services.http.response.headers.x-powered-by: "PHP"'),
]

# FOFA  (popular in Asian security research community)
FOFA_QUERIES: List[str] = [
    *[f'header="X-Powered-By: PHP/{minor}"' for minor in VULN_MINORS],
    'title="phpMyAdmin" && header="PHP"',
    'body="phpMyAdmin" && header="PHP/8"',
    'body="Fatal error" && body="PHP 8.2"',
    'body="Fatal error" && body="PHP 8.3"',
    'body="Fatal error" && body="PHP 8.4"',
]

# ZoomEye  (Knownsec internet scanner)
ZOOMEYE_DORKS: List[str] = [
    *[f'header:"X-Powered-By: PHP/{minor}"' for minor in VULN_MINORS],
    *[f'app:"PHP" ver:"{minor}"' for minor in VULN_MINORS],
    'title:"phpMyAdmin" app:"PHP"',
    'header:"X-Powered-By: PHP/8"',
]

# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------


class BackendFatalError(Exception):
    """
    Raised by a backend generator when a condition makes retrying every
    remaining dork pointless (e.g. plan too low, bad credentials, IP ban).
    The orchestrator catches this, logs the message, and skips all remaining
    dorks for that backend instead of hammering the API 12 more times.
    """


class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


def colorize(text: str, color: str, no_color: bool = False) -> str:
    return text if no_color else f"{color}{text}{Colors.RESET}"


def log(msg: str, color: str = "", no_color: bool = False, quiet: bool = False) -> None:
    if not quiet:
        print(colorize(msg, color, no_color), file=sys.stderr)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def normalize_url(raw: str) -> Optional[str]:
    """Return scheme://host[:port] or None if unparseable."""
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlsplit(raw)
        if p.scheme not in ("http", "https") or not p.netloc:
            return None
        netloc = p.netloc.rsplit("@", 1)[-1]  # strip credentials
        return urlunsplit((p.scheme, netloc, "", "", ""))
    except ValueError:
        return None


def extract_hrefs(html: str) -> List[str]:
    """Extract href URL values from raw HTML."""
    return re.findall(r'href=["\']?(https?://[^"\'<>\s]+)', html, re.IGNORECASE)


def extract_google_urls(html: str) -> List[str]:
    """
    Extract result URLs from Google search HTML.

    Google uses two href formats:
      1. Direct:   href="https://example.com/..."
      2. Redirect: href="/url?q=https%3A%2F%2Fexample.com..."
    Both are handled here, and Google's own domains are filtered out.
    """
    urls: List[str] = []
    _GOOGLE_DOMAINS = re.compile(
        r"(google\.|googleusercontent\.|gstatic\.|googleapis\.|googlesyndication\.)",
        re.IGNORECASE,
    )

    # Format 1 — direct https:// hrefs
    for url in re.findall(r'href=["\']?(https?://[^"\'<>\s]+)', html, re.IGNORECASE):
        if not _GOOGLE_DOMAINS.search(urlsplit(url).netloc):
            urls.append(url)

    # Format 2 — /url?q=<encoded> redirect links
    for encoded in re.findall(r'href=["\']?/url\?[^"\'<>\s]*q=(https?[^&"\'<>\s]+)',
                              html, re.IGNORECASE):
        try:
            decoded = unquote(encoded)
            if decoded.startswith("http") and not _GOOGLE_DOMAINS.search(urlsplit(decoded).netloc):
                urls.append(decoded)
        except Exception:
            pass

    return urls


_GOOGLE_BLOCK_SIGNALS = (
    "recaptcha",
    "consent.google.com",
    "before you continue",
    "detected unusual traffic",
    "/sorry/index",
)


def _google_is_blocked(html: str) -> bool:
    low = html.lower()
    return any(sig in low for sig in _GOOGLE_BLOCK_SIGNALS)


def extract_ddg_urls(html: str) -> List[str]:
    """
    Extract destination URLs from DuckDuckGo's `uddg=` redirect parameters.
    DDG wraps results as: //duckduckgo.com/l/?uddg=<url-encoded-url>
    """
    urls: List[str] = []
    for match in re.finditer(r'uddg=([^&"\'<>\s]+)', html):
        try:
            decoded = unquote(match.group(1))
            if decoded.startswith("http"):
                urls.append(decoded)
        except Exception:
            pass
    return urls


# ---------------------------------------------------------------------------
# Shared HTTP session
# ---------------------------------------------------------------------------

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Full browser headers that reduce bot-detection on Google / DDG
_BROWSER_HEADERS = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language":        "en-US,en;q=0.9",
    "Accept-Encoding":        "gzip, deflate, br",
    "Cache-Control":          "no-cache",
    "Pragma":                 "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest":         "document",
    "Sec-Fetch-Mode":         "navigate",
    "Sec-Fetch-Site":         "none",
    "Sec-Fetch-User":         "?1",
    "sec-ch-ua":              '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile":       "?0",
    "sec-ch-ua-platform":     '"Windows"',
}


class _CompatTLSAdapter(HTTPAdapter):
    """
    HTTPS adapter that lowers OpenSSL's cipher security level to SECLEVEL=1.

    Python's default SECLEVEL=2 excludes some cipher suites that certain
    hosts (e.g. html.duckduckgo.com) require, causing SSLv3 handshake
    failures.  SECLEVEL=1 re-enables those suites while still validating
    certificates and hostnames.
    """

    def init_poolmanager(self, *args, **kwargs):
        ctx = _ssl.create_default_context()
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except _ssl.SSLError:
            pass  # platform doesn't support SECLEVEL directive — use defaults
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        ctx = _ssl.create_default_context()
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except _ssl.SSLError:
            pass
        proxy_kwargs["ssl_context"] = ctx
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def make_session() -> "requests.Session":
    if not HAS_REQUESTS:
        raise RuntimeError("pip install requests")
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1.5, status_forcelist=[429, 500, 502, 503])
    adapter = _CompatTLSAdapter(max_retries=retry)  # fixes DDG SSL handshake
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": DEFAULT_UA})
    # Bypass Google's cookie-consent gate (EU / new-account prompts)
    session.cookies.set("CONSENT", "YES+cb", domain=".google.com")
    session.cookies.set("SOCS",    "CAESEwgDEgk2MTE3MzA5MzAaCwjOz-2uBhDGnbAB",
                        domain=".google.com")
    return session


# ---------------------------------------------------------------------------
# Backend: Google (HTML scrape — no key)
# ---------------------------------------------------------------------------

_GOOGLE_BASE  = "https://www.google.com/search"
_GOOGLE_DELAY = 4.0


def google_search(
    query: str,
    max_results: int,
    *,
    session: "requests.Session",
    delay: float = _GOOGLE_DELAY,
) -> Generator[str, None, None]:
    start = 0
    yielded = 0
    per_page = min(10, max_results)
    blocked_warned = False

    while yielded < max_results:
        params = {"q": query, "num": per_page, "start": start, "hl": "en", "gl": "us"}
        try:
            resp = session.get(
                _GOOGLE_BASE,
                params=params,
                headers=_BROWSER_HEADERS,
                timeout=20,
            )
            resp.raise_for_status()
        except Exception as exc:
            log(f"      [!] google: {exc}", Colors.YELLOW)
            break

        if _google_is_blocked(resp.text):
            if not blocked_warned:
                log("      [!] google: bot-detected (CAPTCHA/consent page) — "
                    "try --ddg or --bing for keyless search",
                    Colors.YELLOW)
                blocked_warned = True
            break

        urls = extract_google_urls(resp.text)
        found = False
        for url in urls:
            host = normalize_url(url)
            if host:
                found = True
                yield host
                yielded += 1
                if yielded >= max_results:
                    return

        if not found:
            break
        start += per_page
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Backend: DuckDuckGo (HTML scrape — no key)
# ---------------------------------------------------------------------------

_DDG_BASE  = "https://html.duckduckgo.com/html/"
_DDG_DELAY = 3.0


def ddg_search(
    query: str,
    max_results: int,
    *,
    session: "requests.Session",
    delay: float = _DDG_DELAY,
) -> Generator[str, None, None]:
    """
    POST to DuckDuckGo's no-JS HTML endpoint and extract result URLs.
    Paginates by re-POSTing with the 's' (offset) field from the next-page form.
    """
    form_data: dict = {"q": query, "b": "", "kl": "wt-wt", "df": ""}
    yielded = 0

    while yielded < max_results:
        try:
            resp = session.post(
                _DDG_BASE,
                data=form_data,
                headers={"Accept": "text/html", "Content-Type": "application/x-www-form-urlencoded"},
                timeout=20,
            )
            resp.raise_for_status()
        except Exception as exc:
            log(f"      [!] ddg: {exc}", Colors.YELLOW)
            break

        urls = extract_ddg_urls(resp.text)
        if not urls:
            break

        for url in urls:
            host = normalize_url(url)
            if host:
                yield host
                yielded += 1
                if yielded >= max_results:
                    return

        # Grab next-page form fields (DDG paginates via hidden form)
        next_form = _ddg_next_form(resp.text)
        if not next_form:
            break
        form_data = next_form
        time.sleep(delay)


def _ddg_next_form(html: str) -> Optional[dict]:
    """Parse DDG's 'next page' hidden form, if present."""
    m = re.search(
        r'<form[^>]+action=["\']?/html/["\']?[^>]*>(.*?)</form>',
        html, re.DOTALL | re.IGNORECASE,
    )
    if not m:
        return None
    fields = re.findall(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
        m.group(1), re.IGNORECASE,
    )
    if not fields:
        return None
    result = dict(fields)
    # Only proceed if 's' (offset) field is present — that's the pagination key
    return result if "s" in result else None


# ---------------------------------------------------------------------------
# Backend: Yahoo (HTML scrape — no key)
# ---------------------------------------------------------------------------

_YAHOO_BASE  = "https://search.yahoo.com/search"
_YAHOO_DELAY = 3.0
_YAHOO_SKIP  = re.compile(r"(yahoo\.com|yimg\.com|aol\.com)", re.IGNORECASE)


def yahoo_search(
    query: str,
    max_results: int,
    *,
    session: "requests.Session",
    delay: float = _YAHOO_DELAY,
) -> Generator[str, None, None]:
    start = 1
    yielded = 0
    per_page = min(10, max_results)

    while yielded < max_results:
        params = {"p": query, "n": per_page, "b": start, "pz": per_page}
        try:
            resp = session.get(
                _YAHOO_BASE,
                params=params,
                headers={"Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"},
                timeout=20,
            )
            resp.raise_for_status()
        except Exception as exc:
            log(f"      [!] yahoo: {exc}", Colors.YELLOW)
            break

        found = False
        for url in extract_hrefs(resp.text):
            if _YAHOO_SKIP.search(urlsplit(url).netloc):
                continue
            host = normalize_url(url)
            if host:
                found = True
                yield host
                yielded += 1
                if yielded >= max_results:
                    return

        if not found:
            break
        start += per_page
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Backend: Bing Web Search API
# ---------------------------------------------------------------------------

_BING_BASE = "https://api.bing.microsoft.com/v7.0/search"


def bing_search(
    query: str,
    max_results: int,
    *,
    api_key: str,
    session: "requests.Session",
) -> Generator[str, None, None]:
    offset = 0
    per_page = min(50, max_results)
    yielded = 0

    while yielded < max_results:
        params = {
            "q": query,
            "count": per_page,
            "offset": offset,
            "mkt": "en-US",
            "responseFilter": "Webpages",
        }
        try:
            resp = session.get(
                _BING_BASE,
                params=params,
                headers={"Ocp-Apim-Subscription-Key": api_key},
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log(f"      [!] bing: {exc}", Colors.YELLOW)
            break

        pages = data.get("webPages", {}).get("value", [])
        if not pages:
            break

        for page in pages:
            host = normalize_url(page.get("url", ""))
            if host:
                yield host
                yielded += 1
                if yielded >= max_results:
                    return

        if len(pages) < per_page:
            break
        offset += per_page
        time.sleep(1.0)


# ---------------------------------------------------------------------------
# Backend: Shodan Search API
# ---------------------------------------------------------------------------

_SHODAN_BASE = "https://api.shodan.io/shodan/host/search"


def shodan_search(
    query: str,
    max_results: int,
    *,
    api_key: str,
    session: "requests.Session",
    delay: float = 1.0,
) -> Generator[str, None, None]:
    page = 1
    yielded = 0

    while yielded < max_results:
        params = {"key": api_key, "query": query, "page": page}
        try:
            resp = session.get(_SHODAN_BASE, params=params, timeout=30)
        except Exception as exc:
            log(f"      [!] shodan: {exc}", Colors.YELLOW)
            break

        # 401 / 403 are plan/credential errors — no point retrying other dorks
        if resp.status_code in (401, 403):
            try:
                err_body = resp.json().get("error", resp.text[:120])
            except Exception:
                err_body = resp.text[:120]
            raise BackendFatalError(
                f"Shodan HTTP {resp.status_code}: {err_body}\n"
                "          The /shodan/host/search endpoint requires a paid plan.\n"
                "          Free API keys only support individual IP lookups.\n"
                "          Upgrade: https://account.shodan.io/billing\n"
                "          Free alternatives: --ddg  --censys  --fofa"
            )

        try:
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log(f"      [!] shodan: {exc}", Colors.YELLOW)
            break

        if "error" in data:
            log(f"      [!] shodan API: {data['error']}", Colors.RED)
            break

        matches = data.get("matches", [])
        if not matches:
            break

        for match in matches:
            ip   = match.get("ip_str", "")
            port = match.get("port", 80)
            ssl_block = match.get("ssl") or match.get("https")
            scheme = "https" if (ssl_block or port == 443) else "http"
            if ip:
                host = (f"{scheme}://{ip}:{port}"
                        if port not in (80, 443) else f"{scheme}://{ip}")
                yield host
                yielded += 1
                if yielded >= max_results:
                    return

        if len(matches) < 100:
            break
        page += 1
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Backend: Censys Hosts v2 API
# ---------------------------------------------------------------------------

_CENSYS_BASE = "https://search.censys.io/api/v2/hosts/search"


def censys_search(
    query: str,
    max_results: int,
    *,
    api_id: str,
    api_secret: str,
    session: "requests.Session",
) -> Generator[str, None, None]:
    cursor: Optional[str] = None
    per_page = min(100, max_results)
    yielded = 0

    while yielded < max_results:
        payload: dict = {
            "q": query,
            "per_page": per_page,
            "fields": ["ip", "services.port", "services.service_name"],
        }
        if cursor:
            payload["cursor"] = cursor

        try:
            resp = session.post(
                _CENSYS_BASE,
                json=payload,
                auth=(api_id, api_secret),
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log(f"      [!] censys: {exc}", Colors.YELLOW)
            break

        hits = data.get("result", {}).get("hits", [])
        if not hits:
            break

        for hit in hits:
            ip       = hit.get("ip", "")
            services = hit.get("services", [])
            emitted  = False
            for svc in services:
                svc_name = svc.get("service_name", "").upper()
                if svc_name not in ("HTTP", "HTTPS", ""):
                    continue
                port   = svc.get("port", 80)
                scheme = "https" if (svc_name == "HTTPS" or port == 443) else "http"
                host   = (f"{scheme}://{ip}:{port}"
                          if port not in (80, 443) else f"{scheme}://{ip}")
                yield host
                yielded += 1
                emitted = True
                if yielded >= max_results:
                    return
            if not emitted and ip:
                yield f"https://{ip}"
                yielded += 1
                if yielded >= max_results:
                    return

        cursor = data.get("result", {}).get("links", {}).get("next")
        if not cursor:
            break
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Backend: FOFA
# ---------------------------------------------------------------------------

_FOFA_BASE = "https://fofa.info/api/v1/search/all"


def fofa_search(
    query: str,
    max_results: int,
    *,
    email: str,
    api_key: str,
    session: "requests.Session",
) -> Generator[str, None, None]:
    qb64 = base64.b64encode(query.encode()).decode()
    page = 1
    per_page = min(100, max_results)
    yielded = 0

    while yielded < max_results:
        params = {
            "email":   email,
            "key":     api_key,
            "qbase64": qb64,
            "size":    per_page,
            "page":    page,
            "fields":  "host,ip,port,protocol",
            "full":    "false",
        }
        try:
            resp = session.get(_FOFA_BASE, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log(f"      [!] fofa: {exc}", Colors.YELLOW)
            break

        if data.get("error"):
            log(f"      [!] fofa API: {data.get('errmsg', 'unknown')}", Colors.RED)
            break

        results = data.get("results", [])
        if not results:
            break

        for row in results:
            host_val = row[0] if row else ""
            protocol = row[3] if len(row) > 3 else "http"
            if host_val:
                if "://" not in host_val:
                    host_val = f"{protocol}://{host_val}"
                host = normalize_url(host_val)
                if host:
                    yield host
                    yielded += 1
                    if yielded >= max_results:
                        return

        if len(results) < per_page:
            break
        page += 1
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Backend: ZoomEye (Knownsec)
# ---------------------------------------------------------------------------

_ZOOMEYE_BASE = "https://api.zoomeye.hk/host/search"


def zoomeye_search(
    query: str,
    max_results: int,
    *,
    api_key: str,
    session: "requests.Session",
) -> Generator[str, None, None]:
    """Query ZoomEye host search using a JWT bearer token."""
    page = 1
    yielded = 0

    while yielded < max_results:
        params = {"query": query, "page": page}
        try:
            resp = session.get(
                _ZOOMEYE_BASE,
                params=params,
                headers={"Authorization": f"JWT {api_key}"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log(f"      [!] zoomeye: {exc}", Colors.YELLOW)
            break

        if data.get("error"):
            log(f"      [!] zoomeye API: {data.get('message', 'unknown')}", Colors.RED)
            break

        matches = data.get("matches", [])
        if not matches:
            break

        for match in matches:
            ip       = match.get("ip", "")
            portinfo = match.get("portinfo", {})
            port     = portinfo.get("port", 80)
            service  = portinfo.get("service", "http").lower()
            scheme   = "https" if (port == 443 or service == "https") else "http"
            if ip:
                host = (f"{scheme}://{ip}:{port}"
                        if port not in (80, 443) else f"{scheme}://{ip}")
                yield host
                yielded += 1
                if yielded >= max_results:
                    return

        # ZoomEye returns 20 results per page by default
        if len(matches) < 20:
            break
        page += 1
        time.sleep(1.0)


# ---------------------------------------------------------------------------
# Core orchestrator
# ---------------------------------------------------------------------------


def run_dorks(
    backends: dict,
    max_per_dork: int,
    no_color: bool = False,
    quiet: bool = False,
) -> Generator[str, None, None]:
    """Run all enabled backends and yield deduplicated host URLs."""
    session = make_session()
    seen: Set[str] = set()

    for backend_name, config in backends.items():
        dorks:  List[str] = config["dorks"]
        fn     = config["fn"]
        kwargs = config.get("kwargs", {})

        log(f"\n[*] {backend_name.upper()}  ({len(dorks)} dorks)",
            Colors.CYAN, no_color, quiet)

        fatal = False
        for dork in dorks:
            if fatal:
                break
            log(f"    > {dork}", no_color=no_color, quiet=quiet)
            new_count = 0
            try:
                for host in fn(dork, max_per_dork, session=session, **kwargs):
                    if host and host not in seen:
                        seen.add(host)
                        new_count += 1
                        yield host
            except BackendFatalError as exc:
                # Plan/auth error — log once and skip all remaining dorks
                log(f"      [!] {exc}", Colors.RED, no_color, quiet)
                log(
                    f"      [!] skipping remaining dorks for [{backend_name}]",
                    Colors.YELLOW, no_color, quiet,
                )
                fatal = True
            except Exception as exc:
                log(f"      [!] {exc}", Colors.RED, no_color, quiet)

            if not fatal:
                log(f"      -> {new_count} new host(s)",
                    Colors.GREEN if new_count else Colors.DIM, no_color, quiet)
            time.sleep(1.0)  # polite inter-dork pause


# ---------------------------------------------------------------------------
# Extra dork file loader
# ---------------------------------------------------------------------------


def load_dork_file(path: str) -> Dict[str, List[str]]:
    """
    Load extra dorks from a text file.  Format: one dork per line prefixed
    with the backend name and a colon:

        shodan:"X-Powered-By: PHP/8.3"
        google:intitle:"phpinfo()" "8.3.10"
    """
    extra: Dict[str, List[str]] = {}
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                print(f"[dork-file] line {lineno}: missing backend prefix — skipped",
                      file=sys.stderr)
                continue
            backend, _, dork = line.partition(":")
            backend = backend.strip().lower()
            dork = dork.strip()
            if dork:
                extra.setdefault(backend, []).append(dork)
    return extra


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dork.py",
        description=(
            f"Auto-dorking companion for php2shell-scanner  ({CVES})\n"
            "Finds PHP hosts; feed output into: python scanner.py -l targets.txt\n\n"
            "Store API keys with:  python config.py --set shodan_api_key=xxx"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
env vars (override config.py):
  SHODAN_API_KEY        BING_API_KEY
  CENSYS_API_ID         CENSYS_API_SECRET
  FOFA_EMAIL            FOFA_KEY
  ZOOMEYE_API_KEY

examples:
  python dork.py --shodan -o targets.txt
  python dork.py --google --ddg --yahoo -o targets.txt -n 50
  python dork.py --all -o targets.txt
  python dork.py --list-dorks
  python dork.py --shodan --dork-file extra.dorks -o targets.txt
""",
    )

    # Backend selection
    be = p.add_argument_group("backends (at least one required)")
    be.add_argument("--google",   action="store_true", help="Google scrape       (no key)")
    be.add_argument("--ddg",      action="store_true", help="DuckDuckGo scrape   (no key)")
    be.add_argument("--yahoo",    action="store_true", help="Yahoo scrape        (no key)")
    be.add_argument("--bing",     action="store_true", help="Bing Web Search API")
    be.add_argument("--shodan",   action="store_true", help="Shodan API")
    be.add_argument("--censys",   action="store_true", help="Censys Hosts v2 API")
    be.add_argument("--fofa",     action="store_true", help="FOFA API")
    be.add_argument("--zoomeye",  action="store_true", help="ZoomEye API")
    be.add_argument("--all",      dest="all_backends", action="store_true",
                    help="Enable all backends that have valid credentials")

    # Per-run credential overrides
    creds = p.add_argument_group(
        "credential overrides (CLI > env var > config.py file)"
    )
    creds.add_argument("--shodan-key",      metavar="KEY",    help="Shodan API key")
    creds.add_argument("--bing-key",        metavar="KEY",    help="Bing API key")
    creds.add_argument("--censys-id",       metavar="ID",     help="Censys API ID")
    creds.add_argument("--censys-secret",   metavar="SECRET", help="Censys API secret")
    creds.add_argument("--fofa-email",      metavar="EMAIL",  help="FOFA email")
    creds.add_argument("--fofa-key",        metavar="KEY",    help="FOFA API key")
    creds.add_argument("--zoomeye-key",     metavar="KEY",    help="ZoomEye API key")
    creds.add_argument("--config",          metavar="FILE",
                       help="Custom config file (default: config.local.json)")

    # Output
    out = p.add_argument_group("output")
    out.add_argument("-o", "--output",       metavar="FILE",
                     help="Write host list to FILE (one URL per line)")
    out.add_argument("-n", "--max-per-dork", metavar="N", type=int,
                     help="Max results per dork query (default from config, fallback 100)")
    out.add_argument("--json",     action="store_true", help="Output as JSON array")
    out.add_argument("--no-color", action="store_true", help="Disable coloured output")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="Suppress progress; only print found hosts to stdout")

    # Dork customization
    dg = p.add_argument_group("dork customization")
    dg.add_argument("--list-dorks", action="store_true",
                    help="Print built-in dork catalog and exit")
    dg.add_argument("--dork-file",  metavar="FILE",
                    help="Load extra dorks from file (format: backend:dork per line)")

    return p


def print_catalog(no_color: bool = False) -> None:
    catalog = {
        "google":  GOOGLE_DORKS,
        "ddg":     DDG_DORKS,
        "yahoo":   YAHOO_DORKS,
        "bing":    BING_DORKS,
        "shodan":  SHODAN_DORKS,
        "censys":  CENSYS_QUERIES,
        "fofa":    FOFA_QUERIES,
        "zoomeye": ZOOMEYE_DORKS,
    }
    total = 0
    for name, dorks in catalog.items():
        print(colorize(f"\n[{name.upper()}]  ({len(dorks)} dorks)", Colors.CYAN, no_color))
        for d in dorks:
            print(f"  {d}")
        total += len(dorks)
    print(colorize(f"\ntotal: {total} built-in dorks across 8 backends", Colors.BOLD, no_color))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    no_color = args.no_color
    quiet    = args.quiet

    if args.list_dorks:
        print_catalog(no_color)
        sys.exit(0)

    if not HAS_REQUESTS:
        print("[!] 'requests' is required:  pip install requests", file=sys.stderr)
        sys.exit(1)

    # Load config (file + env vars)
    config_path = Path(args.config) if getattr(args, "config", None) else None
    cfg = _load_config(config_path)

    # Resolve max_per_dork: CLI > config/settings > hardcoded fallback
    max_per_dork: int = (
        args.max_per_dork
        if args.max_per_dork is not None
        else int(cfg.setting("default_max_per_dork", 100))  # type: ignore[arg-type]
    )

    # Resolve credentials  (CLI flag > env var > config file)
    # _load_config already merged env vars into cfg, so we only need to check
    # for explicit CLI flag overrides here.
    shodan_key    = args.shodan_key    or cfg.get("shodan_api_key")
    bing_key      = args.bing_key      or cfg.get("bing_api_key")
    censys_id     = args.censys_id     or cfg.get("censys_api_id")
    censys_secret = args.censys_secret or cfg.get("censys_api_secret")
    fofa_email    = args.fofa_email    or cfg.get("fofa_email")
    fofa_key      = args.fofa_key      or cfg.get("fofa_key")
    zoomeye_key   = args.zoomeye_key   or cfg.get("zoomeye_api_key")

    # Scrape delays from config
    google_delay = float(cfg.setting("google_delay", _GOOGLE_DELAY))  # type: ignore[arg-type]
    ddg_delay    = float(cfg.setting("ddg_delay",    _DDG_DELAY))      # type: ignore[arg-type]
    yahoo_delay  = float(cfg.setting("yahoo_delay",  _YAHOO_DELAY))    # type: ignore[arg-type]
    shodan_delay = float(cfg.setting("shodan_delay", 1.0))             # type: ignore[arg-type]

    # Load extra dorks
    extra: Dict[str, List[str]] = {}
    if args.dork_file:
        try:
            extra = load_dork_file(args.dork_file)
        except OSError as exc:
            print(f"[!] cannot read dork file: {exc}", file=sys.stderr)
            sys.exit(1)

    # Determine active backends
    use_google  = args.google  or args.all_backends
    use_ddg     = args.ddg     or args.all_backends
    use_yahoo   = args.yahoo   or args.all_backends
    use_bing    = args.bing    or args.all_backends
    use_shodan  = args.shodan  or args.all_backends
    use_censys  = args.censys  or args.all_backends
    use_fofa    = args.fofa    or args.all_backends
    use_zoomeye = args.zoomeye or args.all_backends

    if not any([use_google, use_ddg, use_yahoo, use_bing,
                use_shodan, use_censys, use_fofa, use_zoomeye]):
        parser.error(
            "specify at least one backend  "
            "(--google / --ddg / --yahoo / --bing / --shodan / "
            "--censys / --fofa / --zoomeye / --all)"
        )

    backends: dict = {}

    if use_google:
        backends["google"] = {
            "dorks":  GOOGLE_DORKS + extra.get("google", []),
            "fn":     google_search,
            "kwargs": {"delay": google_delay},
        }

    if use_ddg:
        backends["ddg"] = {
            "dorks":  DDG_DORKS + extra.get("ddg", []),
            "fn":     ddg_search,
            "kwargs": {"delay": ddg_delay},
        }

    if use_yahoo:
        backends["yahoo"] = {
            "dorks":  YAHOO_DORKS + extra.get("yahoo", []),
            "fn":     yahoo_search,
            "kwargs": {"delay": yahoo_delay},
        }

    if use_bing:
        if not bing_key:
            log("[!] --bing skipped: set bing_api_key in config.py or BING_API_KEY env",
                Colors.YELLOW, no_color)
        else:
            backends["bing"] = {
                "dorks":  BING_DORKS + extra.get("bing", []),
                "fn":     bing_search,
                "kwargs": {"api_key": bing_key},
            }

    if use_shodan:
        if not shodan_key:
            log("[!] --shodan skipped: set shodan_api_key in config.py or SHODAN_API_KEY env",
                Colors.YELLOW, no_color)
        else:
            backends["shodan"] = {
                "dorks":  SHODAN_DORKS + extra.get("shodan", []),
                "fn":     shodan_search,
                "kwargs": {"api_key": shodan_key, "delay": shodan_delay},
            }

    if use_censys:
        if not censys_id or not censys_secret:
            log("[!] --censys skipped: set censys_api_id + censys_api_secret in config.py",
                Colors.YELLOW, no_color)
        else:
            backends["censys"] = {
                "dorks":  CENSYS_QUERIES + extra.get("censys", []),
                "fn":     censys_search,
                "kwargs": {"api_id": censys_id, "api_secret": censys_secret},
            }

    if use_fofa:
        if not fofa_email or not fofa_key:
            log("[!] --fofa skipped: set fofa_email + fofa_key in config.py",
                Colors.YELLOW, no_color)
        else:
            backends["fofa"] = {
                "dorks":  FOFA_QUERIES + extra.get("fofa", []),
                "fn":     fofa_search,
                "kwargs": {"email": fofa_email, "api_key": fofa_key},
            }

    if use_zoomeye:
        if not zoomeye_key:
            log("[!] --zoomeye skipped: set zoomeye_api_key in config.py or ZOOMEYE_API_KEY env",
                Colors.YELLOW, no_color)
        else:
            backends["zoomeye"] = {
                "dorks":  ZOOMEYE_DORKS + extra.get("zoomeye", []),
                "fn":     zoomeye_search,
                "kwargs": {"api_key": zoomeye_key},
            }

    if not backends:
        print("[!] no backends with valid credentials are enabled", file=sys.stderr)
        sys.exit(1)

    # Banner
    if not quiet:
        total_dorks = sum(len(c["dorks"]) for c in backends.values())
        log(f"\n{Colors.BOLD}php2shell auto-dorker{Colors.RESET}  |  {CVES}",
            no_color=no_color)
        log(f"backends     : {', '.join(backends)}", Colors.CYAN, no_color)
        log(f"dork queries : {total_dorks}", no_color=no_color)
        log(f"max per dork : {max_per_dork}", no_color=no_color)
        vuln_str = "  ".join(
            f"{maj}.{min_}.0–{maj}.{min_}.{p - 1}"
            for (maj, min_), p in FIXED_VERSIONS.items()
        )
        log(f"targets      : PHP {vuln_str}", no_color=no_color)
        if not HAS_CONFIG:
            log("[i] tip: create config.py to store API keys persistently",
                Colors.YELLOW, no_color)

    # Stream results
    hosts: List[str] = []
    outfh = None

    if args.output and not args.json:
        try:
            outfh = open(args.output, "w", encoding="utf-8")
        except OSError as exc:
            print(f"[!] cannot open output file: {exc}", file=sys.stderr)
            sys.exit(1)

    try:
        for host in run_dorks(backends, max_per_dork, no_color, quiet):
            hosts.append(host)
            if quiet:
                print(host, flush=True)
            else:
                log(colorize(f"[+] {host}", Colors.GREEN, no_color), no_color=no_color)
            if outfh:
                outfh.write(host + "\n")
                outfh.flush()
    finally:
        if outfh:
            outfh.close()

    # JSON output (written after collection)
    if args.json:
        payload = json.dumps(hosts, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(payload + "\n")
        else:
            print(payload)

    # Plain-text stdout when no -o given (quiet already streamed live)
    if not args.output and not args.json and not quiet:
        for host in hosts:
            print(host)

    # Summary
    if not quiet:
        log(f"\n[*] {len(hosts)} unique host(s) found", Colors.CYAN, no_color)
        if args.output:
            log(f"[*] saved → {args.output}", Colors.CYAN, no_color)
        log(
            "[*] next step:  python scanner.py -l "
            + (args.output or "<output_file>")
            + " -t 20 -o results.json",
            no_color=no_color,
        )


if __name__ == "__main__":
    main()
