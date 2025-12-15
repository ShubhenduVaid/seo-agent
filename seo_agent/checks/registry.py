from __future__ import annotations

from typing import Any, List, cast

from .broken_links import check_broken_internal_links
from .canonical import check_canonical_target, check_duplicate_and_canonical
from .crawlability import check_crawlability
from .document import check_document_metadata
from .fetch import check_html_truncation
from .links import check_internal_links
from .meta import check_meta_and_headings
from .performance import check_assets, check_mobile, check_speed
from .redirects import check_redirects
from .schema import check_schema
from .security import check_https_security
from .status_and_headers import check_status_and_headers
from .types import CheckSpec

DEFAULT_CHECKS = [
    CheckSpec(check_html_truncation),
    CheckSpec(check_status_and_headers),
    CheckSpec(check_redirects),
    CheckSpec(check_speed),
    CheckSpec(check_assets),
    CheckSpec(check_crawlability, include_on_crawled_pages=False),
    CheckSpec(check_mobile),
    CheckSpec(check_https_security),
    CheckSpec(check_document_metadata),
    CheckSpec(check_schema),
    CheckSpec(check_internal_links),
    CheckSpec(check_broken_internal_links),
    CheckSpec(check_duplicate_and_canonical),
    CheckSpec(check_canonical_target, include_on_crawled_pages=False),
    CheckSpec(check_meta_and_headings),
]


def build_checks(enable_plugins: bool = False) -> List[CheckSpec]:
    checks = list(DEFAULT_CHECKS)
    if enable_plugins:
        checks.extend(_load_plugin_checks())
    return checks


def _load_plugin_checks() -> List[CheckSpec]:
    try:
        from importlib.metadata import entry_points
    except Exception:  # pragma: no cover - extremely defensive
        return []

    try:
        eps = entry_points()
        select = getattr(eps, "select", None)
        if callable(select):
            group = select(group="seo_agent.checks")
        else:
            group = cast(Any, eps).get("seo_agent.checks", [])
    except Exception:  # pragma: no cover - defensive
        return []

    loaded: List[CheckSpec] = []
    for ep in group:
        try:
            obj = ep.load()
        except Exception:
            continue
        if isinstance(obj, CheckSpec):
            loaded.append(obj)
        elif callable(obj):
            loaded.append(CheckSpec(obj))
    return loaded
