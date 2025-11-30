from __future__ import annotations

import textwrap
from typing import Dict, List

from .models import AuditContext, Issue


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


def render_report(context: AuditContext, goal: str, issues: List[Issue]) -> str:
    severity_order = {"critical": 0, "important": 1, "recommended": 2}
    grouped: Dict[str, List[Issue]] = {"critical": [], "important": [], "recommended": []}
    for issue in issues:
        grouped[issue.severity].append(issue)

    for group in grouped.values():
        group.sort(key=lambda i: (severity_order.get(i.severity, 99), i.title))

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
