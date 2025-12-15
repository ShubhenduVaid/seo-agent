from __future__ import annotations

import urllib.parse

from seo_agent.models import AuditContext, Issue

from .types import CheckEnv


def check_redirects(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    issues: list[Issue] = []
    original = urllib.parse.urlparse(context.url)
    final = urllib.parse.urlparse(context.final_url)
    if (original.scheme, original.netloc, original.path) != (final.scheme, final.netloc, final.path):
        issues.append(
            Issue(
                id="crawl.url_redirects",
                severity="important",
                category="crawl",
                title="URL redirects to a different location",
                what=f"Requested URL redirected to {context.final_url}; ensure this is the intended canonical destination.",
                steps=[
                    "Confirm the redirect target is the preferred canonical URL.",
                    "Avoid long redirect chains; use a single 301 to the canonical.",
                    "Align internal links and sitemaps to point directly to the final URL.",
                ],
                outcome="Cleaner crawl paths and consistent canonical signals.",
                validation="Fetch the URL and verify a single 301/308 to the canonical destination.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"requested_url": context.url, "final_url": context.final_url},
            )
        )
    return issues
