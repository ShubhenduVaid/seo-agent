from __future__ import annotations

import json
import textwrap
from typing import Any, Dict, List, Literal, Union, cast

from .models import AuditContext, Issue

OutputFormat = Literal["text", "json", "markdown", "sarif", "github"]

SEVERITY_SCORES = {"critical": 3, "important": 2, "recommended": 1}
IMPACT_WEIGHTS = {"high": 1.3, "medium": 1.0, "low": 0.7}
EFFORT_WEIGHTS = {"low": 0.7, "medium": 1.0, "high": 1.3}
CONFIDENCE_WEIGHTS = {"high": 1.0, "medium": 0.85, "low": 0.7}
CATEGORY_LABELS = {
    "status": "Response & Availability",
    "security": "Security & Headers",
    "crawl": "Crawlability & Indexing",
    "performance": "Performance",
    "content": "Content & Meta",
    "links": "Links & Structure",
    "general": "General",
}
SARIF_LEVELS = {"critical": "error", "important": "warning", "recommended": "note"}
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def render_unreachable(url: str, goal: str, error: str) -> str:
    return textwrap.dedent(
        f"""
        Primary goal: {goal or 'not provided'}
        Could not fetch {url}: {error}

        Critical Issues
        - Site unreachable: Confirm the URL is correct and accessible from the public internet. Check firewalls/CDN blocks and retry.

        Important Optimizations
        - None reported because the page could not be retrieved.

        Recommended Enhancements
        - Once reachable, rerun the audit to surface technical SEO fixes.
        """
    ).strip()


def render_report(
    context: AuditContext,
    goal: str,
    issues: List[Issue],
    fmt: OutputFormat = "text",
    crawl_summary: Dict[str, Any] | None = None,
) -> str:
    grouped: Dict[str, List[Issue]] = {"critical": [], "important": [], "recommended": []}
    for issue in issues:
        grouped[issue.severity].append(issue)

    for group in grouped.values():
        group.sort(key=lambda i: (-_priority_score(i, goal), i.title))

    score_data = _score_issues(issues, goal)
    top_actions = sorted(issues, key=lambda i: (-_priority_score(i, goal), i.title))[:8]
    quick_wins = sorted(
        [i for i in issues if i.impact == "high" and i.effort == "low"],
        key=lambda i: (-_priority_score(i, goal), i.title),
    )[:5]

    if fmt == "json":
        return json.dumps(
            {
                "goal": goal or "not provided",
                "url": context.final_url,
                "status_code": context.status_code,
                "response_time_ms": context.fetch_duration_ms,
                "document_size_bytes": context.content_size,
                "score": score_data,
                "top_five": [_issue_dict(issue, goal) for issue in top_actions[:5]],
                "top_actions": [_issue_dict(issue, goal) for issue in top_actions],
                "quick_wins": [_issue_dict(issue, goal) for issue in quick_wins],
                "issues": {
                    "critical": [_issue_dict(issue, goal) for issue in grouped["critical"]],
                    "important": [_issue_dict(issue, goal) for issue in grouped["important"]],
                    "recommended": [_issue_dict(issue, goal) for issue in grouped["recommended"]],
                },
                "crawl_summary": crawl_summary or {},
            },
            indent=2,
        )

    if fmt == "github":
        return _render_github_summary(context, goal, grouped, score_data, top_actions, quick_wins, crawl_summary)

    if fmt == "sarif":
        return _render_sarif(context, goal, issues)

    if fmt == "markdown":
        return _render_markdown(context, goal, grouped, crawl_summary)

    lines: List[str] = []
    lines.append(f"Primary goal: {goal or 'not provided'}")
    lines.append(f"URL audited: {context.final_url}")
    lines.append(f"Status: {context.status_code or 'unknown'}")
    if context.fetch_duration_ms:
        lines.append(f"Response time: {context.fetch_duration_ms} ms")
    if context.content_size:
        lines.append(f"Document size: {int(context.content_size/1024)} KB")
    lines.append(f"Overall score: {score_data['overall']} / 100")
    lines.append("")
    lines.append("Next actions (recommended order):")
    if not top_actions:
        lines.append("- None detected.")
    else:
        for issue in top_actions:
            page_suffix = f" (page: {issue.page})" if getattr(issue, "page", "") else ""
            lines.append(f"- [{issue.severity}] {issue.title}{page_suffix} (impact: {issue.impact}, effort: {issue.effort})")
    lines.append("")
    lines.append("Quick wins:")
    if not quick_wins:
        lines.append("- None detected.")
    else:
        for issue in quick_wins:
            page_suffix = f" (page: {issue.page})" if getattr(issue, "page", "") else ""
            lines.append(f"- {issue.title}{page_suffix}")
    lines.append("")
    if crawl_summary:
        lines.append("Crawl summary")
        lines.extend(_render_crawl_summary_text(crawl_summary))
        lines.append("")
    lines.append("1. Critical Issues - fix immediately (high impact)")
    lines.extend(_render_issue_group(grouped["critical"]))
    lines.append("")
    lines.append("2. Important Optimizations - fix soon (medium impact)")
    lines.extend(_render_issue_group(grouped["important"]))
    lines.append("")
    lines.append("3. Recommended Enhancements - nice to have")
    lines.extend(_render_issue_group(grouped["recommended"]))

    return "\n".join(lines)


def _render_issue_group(issues: List[Issue]) -> List[str]:
    if not issues:
        return ["- None detected for this category."]

    lines: List[str] = []
    for issue in issues:
        page_suffix = f" (page: {issue.page})" if getattr(issue, "page", "") else ""
        lines.append(f"- {issue.title}{page_suffix}")
        lines.append(f"  What: {issue.what}")
        lines.append("  Fix steps:")
        for step in issue.steps:
            lines.append(f"    - {step}")
        lines.append(f"  Outcome: {issue.outcome}")
        lines.append(f"  Validate: {issue.validation}")
    return lines


def _render_markdown(
    context: AuditContext, goal: str, grouped: Dict[str, List[Issue]], crawl_summary: Dict[str, Any] | None
) -> str:
    sections: List[str] = []
    sections.append("# SEO Audit Report")
    sections.append(f"**Goal:** {goal or 'not provided'}  ")
    sections.append(f"**URL:** {context.final_url}")
    sections.append(f"**Status:** {context.status_code or 'unknown'}")
    if context.fetch_duration_ms:
        sections.append(f"**Response time:** {context.fetch_duration_ms} ms")
    if context.content_size:
        sections.append(f"**Document size:** {int(context.content_size/1024)} KB")
    sections.append("")

    all_issues = grouped["critical"] + grouped["important"] + grouped["recommended"]
    top_actions = sorted(all_issues, key=lambda i: (-_priority_score(i, goal), i.title))[:8]
    quick_wins = sorted(
        [i for i in all_issues if i.impact == "high" and i.effort == "low"],
        key=lambda i: (-_priority_score(i, goal), i.title),
    )[:5]
    sections.append("## Next actions (recommended order)")
    if not top_actions:
        sections.append("- None detected.")
    else:
        for issue in top_actions:
            page_suffix = f" (page: {issue.page})" if getattr(issue, "page", "") else ""
            sections.append(f"- [{issue.severity}] {issue.title}{page_suffix} (impact: {issue.impact}, effort: {issue.effort})")
    sections.append("")
    sections.append("## Quick wins")
    if not quick_wins:
        sections.append("- None detected.")
    else:
        for issue in quick_wins:
            page_suffix = f" (page: {issue.page})" if getattr(issue, "page", "") else ""
            sections.append(f"- {issue.title}{page_suffix}")
    sections.append("")

    def block(title: str, issues: List[Issue]) -> None:
        sections.append(f"## {title}")
        if not issues:
            sections.append("- None detected for this category.")
            return
        for issue in issues:
            sections.append(f"### {issue.title}")
            if getattr(issue, "page", ""):
                sections.append(f"**Page:** {issue.page}")
            sections.append(f"**What:** {issue.what}")
            sections.append("")
            sections.append("**Fix steps:**")
            for step in issue.steps:
                sections.append(f"- {step}")
            sections.append("")
            sections.append(f"**Outcome:** {issue.outcome}")
            sections.append(f"**Validate:** {issue.validation}")
            sections.append("")

    # No category breakdown yet; keep severity buckets for markdown.
    if crawl_summary:
        sections.append("## Crawl summary")
        sections.extend(_render_crawl_summary_markdown(crawl_summary))
        sections.append("")

    block("1. Critical Issues – fix immediately (high impact)", grouped["critical"])
    block("2. Important Optimizations – fix soon (medium impact)", grouped["important"])
    block("3. Recommended Enhancements – nice to have", grouped["recommended"])
    return "\n".join(sections)


def _render_github_summary(
    context: AuditContext,
    goal: str,
    grouped: Dict[str, List[Issue]],
    score_data: Dict[str, Union[int, Dict[str, int]]],
    top_actions: List[Issue],
    quick_wins: List[Issue],
    crawl_summary: Dict[str, Any] | None,
) -> str:
    lines: List[str] = []
    lines.append("# SEO Audit Summary")
    lines.append(f"**URL:** {context.final_url}")
    lines.append(f"**Goal:** {goal or 'not provided'}")
    lines.append(f"**Status:** {context.status_code or 'unknown'}")
    if context.fetch_duration_ms:
        lines.append(f"**Response time:** {context.fetch_duration_ms} ms")
    if context.content_size:
        lines.append(f"**Document size:** {int(context.content_size/1024)} KB")
    lines.append(f"**Overall score:** {score_data['overall']} / 100")
    lines.append("")

    lines.append("## Issue counts")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    lines.append(f"| Critical | {len(grouped['critical'])} |")
    lines.append(f"| Important | {len(grouped['important'])} |")
    lines.append(f"| Recommended | {len(grouped['recommended'])} |")
    lines.append("")

    lines.append("## Top actions")
    if not top_actions:
        lines.append("- None detected.")
    else:
        for issue in top_actions[:5]:
            page_suffix = f" (page: {issue.page})" if getattr(issue, "page", "") else ""
            lines.append(
                f"- [{issue.severity}] {issue.title}{page_suffix} (impact: {issue.impact}, effort: {issue.effort})"
            )
    lines.append("")

    lines.append("## Quick wins")
    if not quick_wins:
        lines.append("- None detected.")
    else:
        for issue in quick_wins:
            page_suffix = f" (page: {issue.page})" if getattr(issue, "page", "") else ""
            lines.append(f"- {issue.title}{page_suffix}")
    lines.append("")

    if crawl_summary:
        lines.append("## Crawl summary")
        lines.extend(_render_crawl_summary_markdown(crawl_summary))
        lines.append("")

    lines.append("Generated by SEO Audit Agent.")
    return "\n".join(lines)


def _render_crawl_summary_text(summary: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    pages = int(summary.get("pages_crawled", 0))
    lines.append(f"- Sampled {pages} additional page(s)")
    dup_titles = cast(List[Dict[str, Any]], summary.get("duplicate_titles") or [])
    dup_h1 = cast(List[Dict[str, Any]], summary.get("duplicate_h1") or [])
    dup_desc = cast(List[Dict[str, Any]], summary.get("duplicate_descriptions") or [])
    if not dup_titles and not dup_h1 and not dup_desc:
        lines.append("- No duplicate titles, H1s, or descriptions detected in the sample.")
        return lines
    if dup_titles:
        for item in dup_titles:
            pages_list = ", ".join(item.get("pages", [])[:3])
            lines.append(f"- Duplicate title \"{item.get('value','')}\" on {len(item.get('pages', []))} pages: {pages_list}")
    if dup_h1:
        for item in dup_h1:
            pages_list = ", ".join(item.get("pages", [])[:3])
            value = item.get("value", "") or ""
            snippet = value if len(value) <= 60 else value[:60] + "..."
            lines.append(f"- Duplicate H1 \"{snippet}\" on {len(item.get('pages', []))} pages: {pages_list}")
    if dup_desc:
        for item in dup_desc:
            pages_list = ", ".join(item.get("pages", [])[:3])
            value = item.get("value", "") or ""
            snippet = value if len(value) <= 60 else value[:60] + "..."
            lines.append(f"- Duplicate meta description \"{snippet}\" on {len(item.get('pages', []))} pages: {pages_list}")
    return lines


def _render_crawl_summary_markdown(summary: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    pages = int(summary.get("pages_crawled", 0))
    lines.append(f"- Sampled {pages} additional page(s)")
    dup_titles = cast(List[Dict[str, Any]], summary.get("duplicate_titles") or [])
    dup_h1 = cast(List[Dict[str, Any]], summary.get("duplicate_h1") or [])
    dup_desc = cast(List[Dict[str, Any]], summary.get("duplicate_descriptions") or [])
    if not dup_titles and not dup_h1 and not dup_desc:
        lines.append("- No duplicate titles, H1s, or descriptions detected in the sample.")
        return lines
    if dup_titles:
        lines.append("- Duplicate titles:")
        for item in dup_titles:
            pages_list = ", ".join(item.get("pages", [])[:3])
            lines.append(f"  - \"{item.get('value','')}\" on {len(item.get('pages', []))} pages (e.g., {pages_list})")
    if dup_h1:
        lines.append("- Duplicate H1s:")
        for item in dup_h1:
            pages_list = ", ".join(item.get("pages", [])[:3])
            value = item.get("value", "") or ""
            snippet = value if len(value) <= 60 else value[:60] + "..."
            lines.append(f"  - \"{snippet}\" on {len(item.get('pages', []))} pages (e.g., {pages_list})")
    if dup_desc:
        lines.append("- Duplicate meta descriptions:")
        for item in dup_desc:
            pages_list = ", ".join(item.get("pages", [])[:3])
            value = item.get("value", "") or ""
            snippet = value if len(value) <= 60 else value[:60] + "..."
            lines.append(f"  - \"{snippet}\" on {len(item.get('pages', []))} pages (e.g., {pages_list})")
    return lines


def _render_sarif(context: AuditContext, goal: str, issues: List[Issue]) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for issue in issues:
        if issue.id not in rules:
            rules[issue.id] = _sarif_rule(issue)
        message_text = issue.title
        if issue.what:
            message_text = f"{issue.title}: {issue.what}"
        location_uri = issue.page or context.final_url
        result: Dict[str, Any] = {
            "ruleId": issue.id,
            "level": _sarif_level(issue.severity),
            "message": {"text": message_text},
            "properties": {
                "severity": issue.severity,
                "category": issue.category,
                "impact": issue.impact,
                "effort": issue.effort,
                "confidence": issue.confidence,
                "priority_score": round(_priority_score(issue, goal), 4),
                "page": issue.page,
                "evidence": issue.evidence,
            },
        }
        if location_uri:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location_uri},
                    }
                }
            ]
        results.append(result)

    sarif: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SEO Audit Agent",
                        "informationUri": "https://github.com/ShubhenduVaid/seo-agent",
                        "rules": list(rules.values()),
                    }
                },
                "properties": {
                    "goal": goal or "not provided",
                    "url": context.final_url,
                    "status_code": context.status_code,
                    "response_time_ms": context.fetch_duration_ms,
                    "document_size_bytes": context.content_size,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_rule(issue: Issue) -> Dict[str, Any]:
    return {
        "id": issue.id,
        "name": issue.id,
        "shortDescription": {"text": issue.title},
        "fullDescription": {"text": issue.what},
        "help": {"text": _sarif_help_text(issue)},
        "defaultConfiguration": {"level": _sarif_level(issue.severity)},
        "properties": {
            "category": issue.category,
            "severity": issue.severity,
            "impact": issue.impact,
            "effort": issue.effort,
            "confidence": issue.confidence,
        },
    }


def _sarif_help_text(issue: Issue) -> str:
    lines = [issue.title]
    if issue.what:
        lines.append(f"What: {issue.what}")
    if issue.steps:
        lines.append("Fix steps:")
        for step in issue.steps:
            lines.append(f"- {step}")
    if issue.outcome:
        lines.append(f"Outcome: {issue.outcome}")
    if issue.validation:
        lines.append(f"Validate: {issue.validation}")
    return "\n".join(lines)


def _sarif_level(severity: str) -> str:
    return SARIF_LEVELS.get(severity, "warning")


def _score_issues(issues: List[Issue], goal: str) -> Dict[str, Union[int, Dict[str, int]]]:
    per_cat: Dict[str, float] = {}
    total: float = 0.0
    max_total: float = 0.0
    weights = _goal_weights(goal)
    for issue in issues:
        sev_score = SEVERITY_SCORES.get(issue.severity, 0)
        cat = issue.category or "general"
        weight = weights.get(cat, 1.0)
        weighted = sev_score * weight
        per_cat[cat] = per_cat.get(cat, 0.0) + weighted * 1000  # scaled to reduce float drift
        total += weighted
        max_total += 3 * weight  # assume each issue could be critical max weight

    # Normalize to 100
    overall = int((total / max_total) * 100) if max_total else 100
    # Clip to bounds
    overall = max(0, min(100, overall))

    per_cat_normalized: Dict[str, int] = {}
    for cat, score in per_cat.items():
        possible = 3 * sum(1 for i in issues if (i.category or "general") == cat) * weights.get(cat, 1.0)
        per_cat_normalized[cat] = int((score / 1000) / possible * 100) if possible else 100

    return {
        "overall": overall,
        "by_category": {CATEGORY_LABELS.get(k, k): v for k, v in per_cat_normalized.items()},
    }


def _goal_weights(goal: str) -> Dict[str, float]:
    goal_lower = (goal or "").lower()
    weights = {
        "performance": 1.0,
        "content": 1.0,
        "links": 1.0,
        "crawl": 1.0,
        "security": 1.0,
        "status": 1.0,
        "general": 1.0,
    }
    if any(term in goal_lower for term in ["traffic", "growth", "conversion"]):
        weights["performance"] = 1.3
        weights["content"] = 1.2
        weights["links"] = 1.1
    if any(term in goal_lower for term in ["migration", "canonical", "consolidation"]):
        weights["crawl"] = 1.2
        weights["status"] = 1.1
    if any(term in goal_lower for term in ["security", "trust"]):
        weights["security"] = 1.3
    return weights


def _weighted_severity(issue: Issue, goal: str) -> float:
    weights = _goal_weights(goal)
    return SEVERITY_SCORES.get(issue.severity, 0) * weights.get(issue.category or "general", 1.0)


def _priority_score(issue: Issue, goal: str) -> float:
    base = _weighted_severity(issue, goal)
    impact = IMPACT_WEIGHTS.get(getattr(issue, "impact", "medium"), 1.0)
    effort = EFFORT_WEIGHTS.get(getattr(issue, "effort", "medium"), 1.0)
    confidence = CONFIDENCE_WEIGHTS.get(getattr(issue, "confidence", "medium"), 0.85)
    return (base * impact * confidence) / max(effort, 0.01)


def _issue_dict(issue: Issue, goal: str) -> Dict[str, Any]:
    data: Dict[str, Any] = dict(issue.__dict__)
    data["priority_score"] = round(_priority_score(issue, goal), 4)
    return data
