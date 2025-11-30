from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Issue:
    severity: str  # expected: critical, important, recommended
    title: str
    what: str
    steps: List[str]
    outcome: str
    validation: str


@dataclass
class AuditContext:
    url: str
    final_url: str
    html: str
    headers: Dict[str, str]
    robots_txt: Optional[str]
    robots_error: Optional[str]
    sitemap_urls: List[str]
    analyzer: "SimpleHTMLAnalyzer"


@dataclass
class FetchResult:
    body: str
    final_url: str
    headers: Dict[str, str]
    error: Optional[str]


@dataclass
class RobotsResult:
    content: Optional[str]
    error: Optional[str]
    sitemap_urls: List[str]
