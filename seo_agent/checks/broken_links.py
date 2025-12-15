from __future__ import annotations

import urllib.parse
from typing import Dict, List

from seo_agent.models import AuditContext, Issue

from .types import CheckEnv


def check_broken_internal_links(context: AuditContext, env: CheckEnv) -> list[Issue]:
    if not env.check_links or env.link_check_limit_per_page <= 0:
        return []

    domain = urllib.parse.urlparse(context.final_url).netloc.lower()
    candidates: List[str] = []
    for href in context.analyzer.links:
        resolved = urllib.parse.urljoin(context.final_url, href)
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme not in {"http", "https"}:
            continue
        if parsed.netloc.lower() != domain:
            continue
        path = parsed.path or "/"
        normalized = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
        if normalized not in candidates:
            candidates.append(normalized)

    checked_urls = candidates[: env.link_check_limit_per_page]
    if not checked_urls:
        return []

    broken: List[Dict[str, object]] = []
    for url in checked_urls:
        res = env.head(url, verify_ssl=env.verify_ssl, timeout=env.timeout, user_agent=env.user_agent)
        if res.error:
            broken.append({"url": url, "status_code": res.status_code, "error": res.error})
            continue
        if res.status_code == 405:
            continue
        if res.status_code >= 400:
            broken.append({"url": url, "status_code": res.status_code})

    if not broken:
        return []

    sample = ", ".join(str(b.get("url", "")) for b in broken[:3])
    return [
        Issue(
            id="crawl.internal_links_broken",
            severity="important",
            category="crawl",
            title="Broken internal links detected",
            what=f"{len(broken)} of {len(checked_urls)} sampled internal link(s) returned an error. Examples: {sample}",
            steps=[
                "Update internal links to point to the correct canonical 200 URLs.",
                "Add 301 redirects for moved content to preserve equity and avoid 404s.",
                "Fix navigation/footer/template links first to remove repeated broken URLs sitewide.",
            ],
            outcome="Cleaner crawl paths, better UX, and fewer 404s in crawl reports.",
            validation="Re-run the audit with link checking enabled and confirm internal links return 200.",
            impact="medium",
            effort="medium",
            confidence="medium",
            evidence={"checked": checked_urls, "broken": broken[:10]},
        )
    ]

