from __future__ import annotations

from seo_agent.constants import MAX_HTML_BYTES
from seo_agent.models import AuditContext, Issue

from .types import CheckEnv


def check_html_truncation(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    if not context.truncated:
        return []
    return [
        Issue(
            id="fetch.html_truncated",
            severity="recommended",
            category="general",
            title="HTML was truncated during fetch",
            what=f"The HTML response exceeded the safety limit ({int(MAX_HTML_BYTES/1024)} KB) and was truncated; some findings may be incomplete.",
            steps=[
                "Rerun the audit for a more specific URL (e.g., a single page instead of a very large HTML response).",
                "Reduce inline scripts/styles and server-side rendered payload size.",
                "If this is a SPA, ensure server returns meaningful HTML (not a large JSON blob).",
            ],
            outcome="More complete and reliable audit results.",
            validation="Confirm the audited page returns a normal-sized HTML document and rerun the audit.",
            impact="medium",
            effort="medium",
            confidence="high",
            evidence={
                "max_html_bytes": MAX_HTML_BYTES,
                "bytes_read": context.content_size,
                "content_type": context.content_type,
            },
        )
    ]
