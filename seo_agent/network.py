from __future__ import annotations

import ssl
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import List

from .constants import DEFAULT_TIMEOUT, MAX_HTML_BYTES, USER_AGENT
from .models import FetchResult, HeadResult, RobotsResult


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if not parsed.scheme:
        parsed = parsed._replace(scheme="https")
    elif parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.netloc and parsed.path:
        path_parts = parsed.path.split("/", 1)
        host = path_parts[0]
        path = f"/{path_parts[1]}" if len(path_parts) > 1 else ""
        parsed = parsed._replace(netloc=host, path=path)
    return urllib.parse.urlunparse(parsed)


def fetch_url(
    url: str,
    verify_ssl: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = USER_AGENT,
) -> FetchResult:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    context = None if verify_ssl else ssl._create_unverified_context()
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            status_code = getattr(resp, "status", None) or resp.getcode() or 0
            content_type = resp.headers.get("Content-Type", "") or ""
            mime_type = ""
            try:
                mime_type = resp.headers.get_content_type()
            except Exception:  # pragma: no cover - extremely defensive
                mime_type = ""
            if mime_type and mime_type not in {"text/html", "application/xhtml+xml"}:
                duration_ms = int((time.monotonic() - start) * 1000)
                return FetchResult(
                    body="",
                    final_url=resp.geturl(),
                    headers=headers,
                    status_code=status_code,
                    error=f"Unsupported content type: {mime_type}",
                    duration_ms=duration_ms,
                    content_size=0,
                    content_type=content_type,
                    truncated=False,
                )

            body_bytes = resp.read(MAX_HTML_BYTES + 1)
            truncated = len(body_bytes) > MAX_HTML_BYTES
            if truncated:
                body_bytes = body_bytes[:MAX_HTML_BYTES]
            encoding = resp.headers.get_content_charset() or "utf-8"
            body = body_bytes.decode(encoding, errors="ignore")
            duration_ms = int((time.monotonic() - start) * 1000)
            return FetchResult(
                body=body,
                final_url=resp.geturl(),
                headers=headers,
                status_code=status_code,
                error=None,
                duration_ms=duration_ms,
                content_size=len(body_bytes),
                content_type=content_type,
                truncated=truncated,
            )
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return FetchResult(
            body="",
            final_url=url,
            headers={},
            status_code=0,
            error=str(exc),
            duration_ms=duration_ms,
            content_size=0,
            content_type="",
            truncated=False,
        )


def load_robots_and_sitemaps(
    url: str,
    verify_ssl: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = USER_AGENT,
) -> RobotsResult:
    parsed = urllib.parse.urlparse(url)
    robots_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
    req = urllib.request.Request(robots_url, headers={"User-Agent": user_agent})
    context = None if verify_ssl else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read().decode(resp.headers.get_content_charset() or "utf-8", errors="ignore")
            sitemap_urls = extract_sitemaps_from_robots(body)
            return RobotsResult(content=body, error=None, sitemap_urls=sitemap_urls)
    except Exception as exc:
        return RobotsResult(content=None, error=str(exc), sitemap_urls=[])


def extract_sitemaps_from_robots(robots: str) -> List[str]:
    sitemaps = []
    for line in robots.splitlines():
        if line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    return sitemaps


def load_sitemap_urls(
    sitemap_urls: List[str],
    verify_ssl: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = USER_AGENT,
    max_sitemaps: int = 2,
) -> List[str]:
    """Fetch a small sample of sitemap URLs to seed crawling."""
    discovered: List[str] = []
    for sitemap_url in sitemap_urls[:max_sitemaps]:
        req = urllib.request.Request(sitemap_url, headers={"User-Agent": user_agent})
        context = None if verify_ssl else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                body = resp.read().decode(resp.headers.get_content_charset() or "utf-8", errors="ignore")
                discovered.extend(_extract_urls_from_sitemap(body))
        except Exception:
            continue
    return discovered


def _extract_urls_from_sitemap(body: str) -> List[str]:
    body_strip = body.strip()
    if not body_strip:
        return []
    # Try XML parsing first.
    try:
        root = ET.fromstring(body_strip)
        return [loc.text.strip() for loc in root.findall(".//{*}loc") if loc.text]
    except ET.ParseError:
        pass
    # Fallback to newline-delimited URLs (common for text sitemaps).
    urls: List[str] = []
    for line in body_strip.splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)
    return urls


def head_request(
    url: str,
    verify_ssl: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = USER_AGENT,
) -> HeadResult:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent}, method="HEAD")
    context = None if verify_ssl else ssl._create_unverified_context()
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            status_code = getattr(resp, "status", None) or resp.getcode() or 0
            duration_ms = int((time.monotonic() - start) * 1000)
            return HeadResult(headers=headers, status_code=status_code, error=None, duration_ms=duration_ms)
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return HeadResult(headers={}, status_code=0, error=str(exc), duration_ms=duration_ms)
