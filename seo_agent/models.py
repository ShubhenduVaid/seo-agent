from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .analyzer import SimpleHTMLAnalyzer


Impact = Literal["high", "medium", "low"]
Effort = Literal["high", "medium", "low"]
Confidence = Literal["high", "medium", "low"]


@dataclass
class Issue:
    id: str  # stable identifier (e.g., "content.title_missing")
    severity: str  # expected: critical, important, recommended
    title: str
    what: str
    steps: List[str]
    outcome: str
    validation: str
    category: str = "general"
    page: str = ""
    impact: Impact = "medium"
    effort: Effort = "medium"
    confidence: Confidence = "medium"
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditContext:
    url: str
    final_url: str
    status_code: int
    html: str
    headers: Dict[str, str]
    robots_txt: Optional[str]
    robots_error: Optional[str]
    sitemap_urls: List[str]
    analyzer: "SimpleHTMLAnalyzer"
    fetch_duration_ms: int = 0
    content_size: int = 0
    content_type: str = ""
    truncated: bool = False


@dataclass
class FetchResult:
    body: str
    final_url: str
    headers: Dict[str, str]
    status_code: int
    error: Optional[str]
    duration_ms: int = 0
    content_size: int = 0
    content_type: str = ""
    truncated: bool = False


@dataclass
class HeadResult:
    headers: Dict[str, str]
    status_code: int
    error: Optional[str]
    duration_ms: int = 0


@dataclass
class RobotsResult:
    content: Optional[str]
    error: Optional[str]
    sitemap_urls: List[str]
