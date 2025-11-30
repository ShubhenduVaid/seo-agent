from __future__ import annotations

import json
import textwrap
from typing import Dict, List, Literal, Union

from .models import AuditContext, Issue

OutputFormat = Literal["text", "json", "markdown"]


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


def render_report(context: AuditContext, goal: str, issues: List[Issue], fmt: OutputFormat = "text") -> str:
    severity_order = {"critical": 0, "important": 1, "recommended": 2}
    grouped: Dict[str, List[Issue]] = {"critical": [], "important": [], "recommended": []}
    for issue in issues:
        grouped[issue.severity].append(issue)

    for group in grouped.values():
        group.sort(key=lambda i: (severity_order.get(i.severity, 99), i.title))

    if fmt == "json":
        return json.dumps(
            {
                "goal": goal or "not provided",
                "url": context.final_url,
                "issues": {
                    "critical": [issue.__dict__ for issue in grouped["critical"]],
                    "important": [issue.__dict__ for issue in grouped["important"]],
                    "recommended": [issue.__dict__ for issue in grouped["recommended"]],
                },
            },
            indent=2,
        )

    if fmt == "markdown":
        return _render_markdown(context, goal, grouped)

    lines: List[str] = []
    lines.append(f"Primary goal: {goal or 'not provided'}")
    lines.append(f"URL audited: {context.final_url}")
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
        lines.append(f"- {issue.title}")
        lines.append(f"  What: {issue.what}")
        lines.append("  Fix steps:")
        for step in issue.steps:
            lines.append(f"    - {step}")
        lines.append(f"  Outcome: {issue.outcome}")
        lines.append(f"  Validate: {issue.validation}")
    return lines


def _render_markdown(context: AuditContext, goal: str, grouped: Dict[str, List[Issue]]) -> str:
    sections: List[str] = []
    sections.append(f"# SEO Audit Report")
    sections.append(f"**Goal:** {goal or 'not provided'}  ")
    sections.append(f"**URL:** {context.final_url}")
    sections.append("")

    def block(title: str, issues: List[Issue]) -> None:
        sections.append(f"## {title}")
        if not issues:
            sections.append("- None detected for this category.")
            return
        for issue in issues:
            sections.append(f"### {issue.title}")
            sections.append(f"**What:** {issue.what}")
            sections.append("")
            sections.append("**Fix steps:**")
            for step in issue.steps:
                sections.append(f"- {step}")
            sections.append("")
            sections.append(f"**Outcome:** {issue.outcome}")
            sections.append(f"**Validate:** {issue.validation}")
            sections.append("")

    block("1. Critical Issues – fix immediately (high impact)", grouped["critical"])
    block("2. Important Optimizations – fix soon (medium impact)", grouped["important"])
    block("3. Recommended Enhancements – nice to have", grouped["recommended"])
    return "\n".join(sections)
