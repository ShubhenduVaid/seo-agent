from __future__ import annotations

import csv
import urllib.parse
from typing import Dict, Optional

from seo_agent.network import normalize_url


def load_gsc_pages_csv(path: str) -> Dict[str, Dict[str, float]]:
    """Load a Search Console 'Pages' performance export CSV.

    Expected columns (case-insensitive; variants supported):
    - page/url
    - clicks (optional)
    - impressions (optional)
    - ctr (optional; may be percent)
    - position (optional)
    """
    metrics: Dict[str, Dict[str, float]] = {}
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return {}
        field_map = {name.strip().lower(): name for name in reader.fieldnames if name}

        page_col = _first_present(field_map, ["page", "url"])
        if not page_col:
            return {}
        clicks_col = _first_present(field_map, ["clicks"])
        impressions_col = _first_present(field_map, ["impressions"])
        ctr_col = _first_present(field_map, ["ctr"])
        position_col = _first_present(field_map, ["position", "average position", "avg position"])

        for row in reader:
            raw_page = (row.get(page_col) or "").strip()
            page = _canonicalize_page_url(raw_page)
            if not page:
                continue

            clicks = _to_float(row.get(clicks_col) if clicks_col else None)
            impressions = _to_float(row.get(impressions_col) if impressions_col else None)
            ctr = _to_float(row.get(ctr_col) if ctr_col else None, percent=True)
            position = _to_float(row.get(position_col) if position_col else None)

            existing = metrics.get(page, {"clicks": 0.0, "impressions": 0.0})
            if clicks is not None:
                existing["clicks"] = existing.get("clicks", 0.0) + clicks
            if impressions is not None:
                existing["impressions"] = existing.get("impressions", 0.0) + impressions
            if ctr is not None:
                existing["ctr"] = ctr
            if position is not None:
                existing["position"] = position
            metrics[page] = existing

    return metrics


def _canonicalize_page_url(url: str) -> Optional[str]:
    if not url:
        return None
    try:
        normalized = normalize_url(url)
    except ValueError:
        return None
    parsed = urllib.parse.urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path or "/"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _first_present(field_map: Dict[str, str], candidates: list[str]) -> Optional[str]:
    for key in candidates:
        col = field_map.get(key)
        if col:
            return col
    return None


def _to_float(value: Optional[str], percent: bool = False) -> Optional[float]:
    if value is None:
        return None
    s = value.strip()
    if not s:
        return None
    s = s.replace(",", "")
    if percent and s.endswith("%"):
        s = s[:-1].strip()
        try:
            return float(s) / 100.0
        except ValueError:
            return None
    try:
        return float(s)
    except ValueError:
        return None

