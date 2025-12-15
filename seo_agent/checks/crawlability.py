from __future__ import annotations

from seo_agent.models import AuditContext, Issue

from .html import get_meta
from .types import CheckEnv


def check_crawlability(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    issues: list[Issue] = []
    robots_txt = context.robots_txt
    robots_error = context.robots_error

    if robots_error:
        issues.append(
            Issue(
                id="crawl.robots_txt_unreachable",
                severity="important",
                category="crawl",
                title="robots.txt is unreachable",
                what=f"robots.txt could not be fetched ({robots_error}); crawlers cannot confirm crawl rules or sitemap locations.",
                steps=[
                    "Ensure robots.txt is served at the domain root with 200 status and correct permissions.",
                    "Add Sitemap directives in robots.txt to expose all XML sitemaps.",
                    "Monitor availability with uptime checks to avoid intermittent crawl issues.",
                ],
                outcome="Search engines can reliably read crawl directives and discover sitemaps.",
                validation="Fetch robots.txt with curl/wget and confirm 200 status and correct content.",
                impact="medium",
                effort="low",
                confidence="medium",
                evidence={"robots_error": robots_error},
            )
        )
    elif robots_txt and "disallow: /" in robots_txt.lower():
        issues.append(
            Issue(
                id="crawl.robots_txt_blocks_all",
                severity="critical",
                category="crawl",
                title="robots.txt blocks all crawling",
                what="robots.txt contains 'Disallow: /' which prevents search engines from crawling the site.",
                steps=[
                    "Update robots.txt to allow crawling for User-agent: * and scope disallows only to private paths.",
                    "Deploy the corrected robots.txt and purge any CDN cache.",
                    "Re-fetch robots.txt in Search Console/Bing Webmaster Tools.",
                ],
                outcome="Crawlers can access and index pages as intended.",
                validation="Fetch robots.txt and verify Disallow rules are scoped; check Coverage report in Search Console.",
                impact="high",
                effort="low",
                confidence="medium",
                evidence={"match": "disallow: /"},
            )
        )

    if not context.sitemap_urls:
        issues.append(
            Issue(
                id="crawl.sitemap_not_advertised",
                severity="important",
                category="crawl",
                title="XML sitemap not advertised",
                what="No XML sitemap was found in robots.txt; without it, discovery of deep pages is slower.",
                steps=[
                    "Generate XML sitemap(s) covering canonical, indexable URLs only.",
                    "Link the sitemap in robots.txt via 'Sitemap: https://example.com/sitemap.xml'.",
                    "Submit the sitemap in Search Console/Bing Webmaster Tools.",
                ],
                outcome="Faster discovery and fresher indexing of URLs.",
                validation="Fetch robots.txt and sitemap URL; ensure 200 status and valid XML in Search Console.",
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"sitemap_urls_found": len(context.sitemap_urls)},
            )
        )

    meta_robots = get_meta(analyzer, "robots")
    if meta_robots and "noindex" in meta_robots.get("content", "").lower():
        issues.append(
            Issue(
                id="crawl.meta_robots_noindex",
                severity="critical",
                category="crawl",
                title="Page is marked noindex",
                what="Meta robots tag includes 'noindex', preventing the page from appearing in search results.",
                steps=[
                    "Remove 'noindex' from the meta robots tag for pages that should rank.",
                    "Ensure server headers do not include X-Robots-Tag: noindex.",
                    "Re-crawl the URL in Search Console to request indexation after deploying the fix.",
                ],
                outcome="Page becomes eligible for indexing and ranking.",
                validation="Inspect the URL in Search Console; meta robots should show 'index, follow'.",
                impact="high",
                effort="low",
                confidence="high",
                evidence={"meta_robots": meta_robots.get("content", "")},
            )
        )

    return issues
