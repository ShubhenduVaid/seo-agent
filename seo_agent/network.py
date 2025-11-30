from __future__ import annotations

import ssl
import urllib.parse
import urllib.request
from typing import List

from .constants import DEFAULT_TIMEOUT, USER_AGENT
from .models import FetchResult, RobotsResult


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if not parsed.scheme:
        parsed = parsed._replace(scheme="https")
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
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            body_bytes = resp.read()
            encoding = resp.headers.get_content_charset() or "utf-8"
            body = body_bytes.decode(encoding, errors="ignore")
            headers = {k: v for k, v in resp.headers.items()}
            return FetchResult(body=body, final_url=resp.geturl(), headers=headers, error=None)
    except Exception as exc:
        return FetchResult(body="", final_url=url, headers={}, error=str(exc))


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
