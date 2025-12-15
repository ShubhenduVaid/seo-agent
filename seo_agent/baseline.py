from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from .models import Issue

BASELINE_SCHEMA_VERSION = 1


def build_baseline(url: str, goal: str, issues: List[Issue]) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    for issue in issues:
        items.append(
            {
                "id": issue.id,
                "page": issue.page,
                "severity": issue.severity,
                "category": issue.category,
                "title": issue.title,
                "impact": issue.impact,
                "effort": issue.effort,
                "confidence": issue.confidence,
            }
        )
    items.sort(key=lambda i: (i.get("page", ""), i.get("id", "")))
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "url": url,
        "goal": goal or "",
        "issues": items,
    }


def save_baseline(path: str, baseline: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
        f.write("\n")


def load_baseline(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def diff_baselines(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    baseline_items = _index_issues(_get_issues(baseline))
    current_items = _index_issues(_get_issues(current))
    baseline_keys = set(baseline_items.keys())
    current_keys = set(current_items.keys())

    fixed_keys = sorted(baseline_keys - current_keys)
    new_keys = sorted(current_keys - baseline_keys)
    persisting_keys = sorted(baseline_keys & current_keys)

    fixed = [baseline_items[k] for k in fixed_keys]
    new = [current_items[k] for k in new_keys]
    persisting = [current_items[k] for k in persisting_keys]

    def count_by_severity(items: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {"critical": 0, "important": 0, "recommended": 0}
        for item in items:
            sev = (item.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    return {
        "summary": {
            "fixed": len(fixed),
            "new": len(new),
            "persisting": len(persisting),
            "fixed_by_severity": count_by_severity(fixed),
            "new_by_severity": count_by_severity(new),
        },
        "fixed": fixed,
        "new": new,
        "persisting": persisting,
    }


def render_diff_text(diff: Dict[str, Any]) -> str:
    summary = diff.get("summary", {})
    fixed = int(summary.get("fixed", 0))
    new = int(summary.get("new", 0))
    persisting = int(summary.get("persisting", 0))
    fixed_by = summary.get("fixed_by_severity") or {}
    new_by = summary.get("new_by_severity") or {}

    lines = []
    lines.append("Comparison vs baseline")
    lines.append(f"- Fixed: {fixed} (critical: {fixed_by.get('critical', 0)}, important: {fixed_by.get('important', 0)})")
    lines.append(f"- New: {new} (critical: {new_by.get('critical', 0)}, important: {new_by.get('important', 0)})")
    lines.append(f"- Persisting: {persisting}")
    return "\n".join(lines)


def render_diff_markdown(diff: Dict[str, Any]) -> str:
    summary = diff.get("summary", {})
    fixed = int(summary.get("fixed", 0))
    new = int(summary.get("new", 0))
    persisting = int(summary.get("persisting", 0))
    fixed_by = summary.get("fixed_by_severity") or {}
    new_by = summary.get("new_by_severity") or {}

    lines = []
    lines.append("## Comparison vs baseline")
    lines.append(f"- **Fixed:** {fixed} (critical: {fixed_by.get('critical', 0)}, important: {fixed_by.get('important', 0)})")
    lines.append(f"- **New:** {new} (critical: {new_by.get('critical', 0)}, important: {new_by.get('important', 0)})")
    lines.append(f"- **Persisting:** {persisting}")
    return "\n".join(lines)


def _get_issues(baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues = baseline.get("issues")
    return issues if isinstance(issues, list) else []


def _index_issues(items: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    indexed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in items:
        issue_id = str(item.get("id", ""))
        page = str(item.get("page", ""))
        if not issue_id:
            continue
        indexed[(issue_id, page)] = item
    return indexed

