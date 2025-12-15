from __future__ import annotations

import urllib.parse

from seo_agent.models import AuditContext, Issue

from .types import CheckEnv


def check_https_security(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    parsed = urllib.parse.urlparse(context.final_url)
    issues: list[Issue] = []
    if parsed.scheme != "https":
        issues.append(
            Issue(
                id="security.https_missing",
                severity="critical",
                category="security",
                title="Site not served over HTTPS",
                what="URL uses HTTP; insecure transport hurts rankings and user trust.",
                steps=[
                    "Install a valid TLS certificate and configure HTTPS for the domain.",
                    "Redirect all HTTP requests to HTTPS with 301 status.",
                    "Update canonical tags, sitemaps, and internal links to use HTTPS.",
                ],
                outcome="Secure browsing, better trust signals, and alignment with Google's HTTPS-first indexing.",
                validation="Fetch with curl -I http:// and https://; verify 301 to HTTPS and valid certificate.",
                impact="high",
                effort="high",
                confidence="high",
                evidence={"scheme": parsed.scheme},
            )
        )

    if "strict-transport-security" not in {k.lower(): v for k, v in context.headers.items()}:
        issues.append(
            Issue(
                id="security.hsts_missing",
                severity="recommended",
                category="security",
                title="HSTS header not detected",
                what="No Strict-Transport-Security header; browsers may allow HTTP downgrade.",
                steps=[
                    "Serve `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.",
                    "Test for mixed content and fix before enabling preload.",
                    "Submit the domain to the HSTS preload list if appropriate.",
                ],
                outcome="Stronger HTTPS enforcement and protection against downgrade attacks.",
                validation="Check response headers with curl -I; HSTS header should be present with correct max-age.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"present": False},
            )
        )

    return issues
