from __future__ import annotations

from seo_agent.models import AuditContext, Issue

from .types import CheckEnv


def check_status_and_headers(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    issues: list[Issue] = []
    status = context.status_code
    if status >= 500:
        issues.append(
            Issue(
                id="status.http_5xx",
                severity="critical",
                category="status",
                title=f"Page returns {status}",
                what=f"The audited URL responded with HTTP {status}; the page is not serving content reliably.",
                steps=[
                    "Check server logs and application errors for the root cause.",
                    "Restore a healthy 200 response and monitor uptime.",
                    "Verify CDNs/load balancers are not misconfigured.",
                ],
                outcome="Page becomes reachable and eligible for crawling and ranking.",
                validation="Fetch the URL and confirm HTTP 200 with content.",
                impact="high",
                effort="high",
                confidence="high",
                evidence={"status_code": status},
            )
        )
    elif status >= 400:
        issues.append(
            Issue(
                id="status.http_4xx",
                severity="important",
                category="status",
                title=f"Page returns {status}",
                what=f"The audited URL responded with HTTP {status}; crawlers and users will see an error.",
                steps=[
                    "Fix the underlying client error (e.g., missing resource, auth, routing).",
                    "Ensure intended canonical URLs return 200 OK.",
                    "Update internal links/redirects to avoid broken targets.",
                ],
                outcome="Healthy 200 response for the canonical URL.",
                validation="Fetch the URL and confirm HTTP 200 with expected content.",
                impact="high",
                effort="medium",
                confidence="high",
                evidence={"status_code": status},
            )
        )

    headers_lower = {k.lower(): v for k, v in context.headers.items()}
    x_robots = headers_lower.get("x-robots-tag", "").lower()
    if "noindex" in x_robots:
        issues.append(
            Issue(
                id="crawl.x_robots_noindex",
                severity="critical",
                category="crawl",
                title="X-Robots-Tag blocks indexing",
                what="Response header includes X-Robots-Tag with noindex, preventing indexing.",
                steps=[
                    "Remove noindex from X-Robots-Tag for pages that should rank.",
                    "Ensure header configuration in server/CDN does not add noindex globally.",
                    "Re-inspect the URL in Search Console after deployment.",
                ],
                outcome="Page becomes indexable.",
                validation="Check response headers for X-Robots-Tag and confirm index,follow.",
                impact="high",
                effort="low",
                confidence="high",
                evidence={"x_robots_tag": headers_lower.get("x-robots-tag", "")},
            )
        )
    if "nofollow" in x_robots:
        issues.append(
            Issue(
                id="crawl.x_robots_nofollow",
                severity="important",
                category="crawl",
                title="X-Robots-Tag nofollow set",
                what="Response header includes X-Robots-Tag with nofollow; internal links will not pass equity.",
                steps=[
                    "Remove nofollow unless intentionally blocking crawl equity.",
                    "Limit nofollow to specific files/paths if needed.",
                    "Verify server/CDN header rules after deployment.",
                ],
                outcome="Internal links can pass PageRank.",
                validation="Check response headers for X-Robots-Tag and confirm follow.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"x_robots_tag": headers_lower.get("x-robots-tag", "")},
            )
        )

    if "content-security-policy" not in headers_lower:
        issues.append(
            Issue(
                id="security.csp_missing",
                severity="recommended",
                category="security",
                title="Content-Security-Policy header missing",
                what="No Content-Security-Policy header detected; increases risk of injection and mixed content.",
                steps=[
                    "Add a CSP that restricts script/style origins and disallows inline execution where possible.",
                    "Start with report-only to monitor violations before enforcing.",
                    "Update CSP as third-party requirements change.",
                ],
                outcome="Stronger protection against XSS/mixed content issues.",
                validation="Check response headers for Content-Security-Policy; monitor report endpoints for violations.",
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"present": False},
            )
        )

    if "referrer-policy" not in headers_lower:
        issues.append(
            Issue(
                id="security.referrer_policy_missing",
                severity="recommended",
                category="security",
                title="Referrer-Policy header missing",
                what="No Referrer-Policy header detected; referrer data may be over-shared or inconsistent.",
                steps=[
                    "Set Referrer-Policy to a privacy-safe default (e.g., strict-origin-when-cross-origin).",
                    "Test key journeys to ensure analytics still receive necessary data.",
                    "Apply consistently across the site via server/CDN.",
                ],
                outcome="Consistent, privacy-aware referrer handling.",
                validation="Check response headers for Referrer-Policy with the desired value.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"present": False},
            )
        )

    xcto = headers_lower.get("x-content-type-options", "").lower()
    if "nosniff" not in xcto:
        issues.append(
            Issue(
                id="security.xcto_nosniff_missing",
                severity="recommended",
                category="security",
                title="X-Content-Type-Options missing nosniff",
                what="X-Content-Type-Options header is missing or not set to nosniff; increases MIME sniffing risk.",
                steps=[
                    "Add `X-Content-Type-Options: nosniff` to all HTML/JS/CSS responses.",
                    "Ensure proxies/CDNs preserve the header.",
                    "Verify static asset responses also include the header.",
                ],
                outcome="Reduced risk of MIME-type confusion attacks.",
                validation="Check response headers for X-Content-Type-Options: nosniff.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"x_content_type_options": headers_lower.get("x-content-type-options", "")},
            )
        )

    if "permissions-policy" not in headers_lower:
        issues.append(
            Issue(
                id="security.permissions_policy_missing",
                severity="recommended",
                category="security",
                title="Permissions-Policy header missing",
                what="No Permissions-Policy header detected; browser features may be unnecessarily exposed.",
                steps=[
                    "Add a Permissions-Policy (e.g., geolocation=(), camera=(), microphone=()).",
                    "Scope only the features your site needs.",
                    "Apply consistently across the site via server/CDN.",
                ],
                outcome="Reduced surface area for browser feature abuse.",
                validation="Check response headers for Permissions-Policy with intended directives.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"present": False},
            )
        )

    if "x-frame-options" not in headers_lower:
        issues.append(
            Issue(
                id="security.x_frame_options_missing",
                severity="recommended",
                category="security",
                title="X-Frame-Options header missing",
                what="No X-Frame-Options header detected; pages may be embeddable in iframes, increasing clickjacking risk.",
                steps=[
                    "Set X-Frame-Options: SAMEORIGIN (or DENY) on HTML responses.",
                    "If framing is needed for specific domains, use CSP frame-ancestors instead.",
                    "Verify CDNs/proxies preserve the header on cached responses.",
                ],
                outcome="Reduced clickjacking risk and tighter framing control.",
                validation="Fetch response headers and confirm X-Frame-Options is present with SAMEORIGIN or DENY.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"present": False},
            )
        )

    return issues
