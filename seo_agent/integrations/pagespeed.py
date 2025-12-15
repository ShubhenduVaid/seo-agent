from __future__ import annotations

import json
from typing import Any, Dict, Optional


def load_pagespeed_metrics(path: str) -> Dict[str, Any]:
    """Load a PageSpeed Insights / Lighthouse JSON file and extract key metrics.

    This is an offline ingestion helper: provide the JSON file via CLI and the
    agent will surface metrics in the report without calling external APIs.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    lighthouse = data.get("lighthouseResult") if isinstance(data, dict) else None
    if not isinstance(lighthouse, dict):
        lighthouse = data if isinstance(data, dict) else {}

    audits = lighthouse.get("audits") if isinstance(lighthouse, dict) else None
    categories = lighthouse.get("categories") if isinstance(lighthouse, dict) else None
    audits = audits if isinstance(audits, dict) else {}
    categories = categories if isinstance(categories, dict) else {}

    def audit_numeric(audit_id: str) -> Optional[float]:
        audit = audits.get(audit_id)
        if not isinstance(audit, dict):
            return None
        value = audit.get("numericValue")
        return float(value) if isinstance(value, (int, float)) else None

    performance_score = None
    perf_cat = categories.get("performance")
    if isinstance(perf_cat, dict):
        score = perf_cat.get("score")
        performance_score = float(score) if isinstance(score, (int, float)) else None

    return {
        "performance_score": performance_score,
        "fcp_ms": audit_numeric("first-contentful-paint"),
        "lcp_ms": audit_numeric("largest-contentful-paint"),
        "cls": audit_numeric("cumulative-layout-shift"),
        "tbt_ms": audit_numeric("total-blocking-time"),
        "speed_index_ms": audit_numeric("speed-index"),
        "inp_ms": audit_numeric("interaction-to-next-paint"),
    }

