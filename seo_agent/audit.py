from __future__ import annotations

import urllib.parse
from typing import Dict, List, Optional

from .analyzer import SimpleHTMLAnalyzer
from .constants import DEFAULT_TIMEOUT, USER_AGENT
from .models import AuditContext, Issue
from .network import fetch_url, load_robots_and_sitemaps, normalize_url
from .reporting import OutputFormat, render_report, render_unreachable


class SeoAuditAgent:
    def __init__(
        self,
        verify_ssl: bool = True,
        user_agent: str = USER_AGENT,
        timeout: int = DEFAULT_TIMEOUT,
        output_format: OutputFormat = "text",
    ) -> None:
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.timeout = timeout
        self.output_format = output_format
        self._checks = [
            self._check_status_and_headers,
            self._check_redirects,
            self._check_speed,
            self._check_crawlability,
            self._check_mobile,
            self._check_https_security,
            self._check_schema,
            self._check_internal_links,
            self._check_duplicate_and_canonical,
            self._check_meta_and_headings,
        ]

    def audit(self, url: str, goal: str) -> str:
        report, _issues = self.audit_with_details(url, goal)
        return report

    def audit_with_details(self, url: str, goal: str) -> tuple[str, List[Issue]]:
        normalized_url = normalize_url(url)
        fetch_result = fetch_url(normalized_url, verify_ssl=self.verify_ssl, timeout=self.timeout, user_agent=self.user_agent)
        if fetch_result.error:
            return render_unreachable(normalized_url, goal, fetch_result.error), []

        analyzer = SimpleHTMLAnalyzer()
        try:
            analyzer.feed(fetch_result.body)
        except Exception as exc:  # pragma: no cover - defensive
            return render_unreachable(normalized_url, goal, f"HTML parsing failed: {exc}"), []

        robots_result = load_robots_and_sitemaps(
            fetch_result.final_url, verify_ssl=self.verify_ssl, timeout=self.timeout, user_agent=self.user_agent
        )
        context = AuditContext(
            url=normalized_url,
            final_url=fetch_result.final_url,
            status_code=fetch_result.status_code,
            html=fetch_result.body,
            headers=fetch_result.headers,
            robots_txt=robots_result.content,
            robots_error=robots_result.error,
            sitemap_urls=robots_result.sitemap_urls,
            analyzer=analyzer,
        )

        issues = self._collect_issues(context)
        return render_report(context, goal, issues, fmt=self.output_format), issues

    def _collect_issues(self, context: AuditContext) -> List[Issue]:
        issues: List[Issue] = []
        for check in self._checks:
            issues.extend(check(context))
        return issues

    def _check_redirects(self, context: AuditContext) -> List[Issue]:
        issues: List[Issue] = []
        original = urllib.parse.urlparse(context.url)
        final = urllib.parse.urlparse(context.final_url)
        if (original.scheme, original.netloc, original.path) != (final.scheme, final.netloc, final.path):
            issues.append(
                Issue(
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
                )
            )
        return issues

    def _check_status_and_headers(self, context: AuditContext) -> List[Issue]:
        issues: List[Issue] = []
        status = context.status_code
        if status >= 500:
            issues.append(
                Issue(
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
                )
            )
        elif status >= 400:
            issues.append(
                Issue(
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
                )
            )

        headers_lower = {k.lower(): v for k, v in context.headers.items()}
        x_robots = headers_lower.get("x-robots-tag", "").lower()
        if "noindex" in x_robots:
            issues.append(
                Issue(
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
                )
            )
        if "nofollow" in x_robots:
            issues.append(
                Issue(
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
                )
            )

        if "content-security-policy" not in headers_lower:
            issues.append(
                Issue(
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
                )
            )

        if "referrer-policy" not in headers_lower:
            issues.append(
                Issue(
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
                )
            )

        xcto = headers_lower.get("x-content-type-options", "").lower()
        if "nosniff" not in xcto:
            issues.append(
                Issue(
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
                )
            )

        if "permissions-policy" not in headers_lower:
            issues.append(
                Issue(
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
                )
            )

        return issues

    def _check_speed(self, context: AuditContext) -> List[Issue]:
        analyzer = context.analyzer
        html_size_kb = len(context.html.encode("utf-8")) / 1024
        script_count = len(analyzer.scripts)
        blocking_scripts = [s for s in analyzer.scripts if not s.get("async") and not s.get("defer")]
        image_count = len(analyzer.images)
        missing_img_sizes = [img for img in analyzer.images if not img.get("width") or not img.get("height")]
        link_hints = [link for link in analyzer.link_tags if link.get("rel") in {"preload", "prefetch"}]

        issues: List[Issue] = []
        if html_size_kb > 1600:
            issues.append(
                Issue(
                    severity="critical",
                    category="performance",
                    title="Page weight is heavy, likely slowing LCP",
                    what=f"HTML+inline content is ~{int(html_size_kb)} KB which is high and will slow First Byte/LCP, especially on mobile.",
                    steps=[
                        "Remove unused inline scripts/styles and move scripts to external files with defer/async.",
                        "Compress text responses with Brotli/Gzip and enable server-level caching (Cache-Control).",
                        "Lazy-load below-the-fold assets and defer non-critical widgets/trackers.",
                    ],
                    outcome="Lower transfer size and faster LCP on mobile/slow connections.",
                    validation="Run Lighthouse or PageSpeed Insights again; LCP and TTFB should drop and the 'Reduce payloads' audit should pass.",
                )
            )
        elif html_size_kb > 900:
            issues.append(
                Issue(
                    severity="important",
                    category="performance",
                    title="Page weight could be trimmed for better Web Vitals",
                    what=f"HTML+inline content is ~{int(html_size_kb)} KB; large payloads hurt LCP/FID, especially on first hit.",
                    steps=[
                        "Minify/compress HTML, strip unused inline JS/CSS, and defer third-party scripts.",
                        "Serve static assets with caching and compression; move heavy JSON blobs to async requests.",
                        "Introduce code-splitting for client JS and lazy-load non-critical components.",
                    ],
                    outcome="Reduced payload improves LCP and interaction readiness.",
                    validation="Profile network waterfall; initial document and main JS bundles should be smaller and load faster.",
                )
            )

        if script_count > 40 or len(blocking_scripts) > 15:
            issues.append(
                Issue(
                    severity="critical",
                    category="performance",
                    title="Too many render-blocking scripts",
                    what=f"{len(blocking_scripts)} scripts load without async/defer out of {script_count} total, delaying rendering and FID.",
                    steps=[
                        "Mark non-critical scripts with defer/async and move them below the fold.",
                        "Remove or delay third-party tags until user interaction; use a tag manager with load rules.",
                        "Inline only critical CSS; avoid inline JS that blocks parsing before first paint.",
                    ],
                    outcome="Faster first render and improved FID/INP scores.",
                    validation="Check waterfall for JS blocking the parser; INP/FID in Lighthouse should improve.",
                )
            )
        elif script_count > 25:
            issues.append(
                Issue(
                    severity="important",
                    category="performance",
                    title="High script count may slow interactivity",
                    what=f"{script_count} scripts detected; heavy JS increases main-thread work and hurts INP.",
                    steps=[
                        "Audit third-party tags; remove duplicates and unnecessary trackers.",
                        "Defer non-essential scripts and split bundles to load only what is needed above the fold.",
                        "Use browser caching and HTTP/2 multiplexing to reduce connection overhead.",
                    ],
                    outcome="Lower JS overhead and better responsiveness.",
                    validation="Profile main-thread in DevTools Performance; total blocking time should decrease.",
                )
            )

        if missing_img_sizes:
            issues.append(
                Issue(
                    severity="important",
                    category="performance",
                    title="Images missing intrinsic size can cause layout shift",
                    what=f"{len(missing_img_sizes)} images lack width/height, increasing CLS risk.",
                    steps=[
                        "Add explicit width and height (or aspect-ratio in CSS) for all images.",
                        "Serve responsive images with srcset/sizes to match device widths.",
                        "Lazy-load offscreen images with loading='lazy' where appropriate.",
                    ],
                    outcome="Reduced layout shifts and improved CLS scores.",
                    validation="Run Lighthouse; CLS should improve and 'Image elements have explicit width and height' should pass.",
                )
            )

        if image_count > 80:
            issues.append(
                Issue(
                    severity="recommended",
                    category="performance",
                    title="Large image count may impact speed",
                    what=f"{image_count} images detected; many requests can slow down LCP and bandwidth-heavy pages.",
                    steps=[
                        "Combine decorative images into CSS backgrounds or sprites where possible.",
                        "Ensure compression (WebP/AVIF) and lazy-load all below-the-fold media.",
                        "Use a CDN with HTTP/2/3 to serve media efficiently.",
                    ],
                    outcome="Fewer render-blocking image requests and better loading on mobile.",
                    validation="Check network waterfalls; image requests should be smaller and deferred.",
                )
            )

        if html_size_kb > 2000 and not link_hints:
            issues.append(
                Issue(
                    severity="recommended",
                    category="performance",
                    title="No resource hints for heavy pages",
                    what="Large document detected but no preload/prefetch hints were found.",
                    steps=[
                        "Add preload for critical CSS/hero images and key fonts.",
                        "Use preconnect for critical third-party origins.",
                        "Remove unused hints and monitor waterfall improvements.",
                    ],
                    outcome="Faster start render and reduced resource discovery time.",
                    validation="Check waterfall; preloaded assets should appear early and reduce blocking.",
                )
            )

        return issues

    def _check_crawlability(self, context: AuditContext) -> List[Issue]:
        analyzer = context.analyzer
        issues: List[Issue] = []
        robots_txt = context.robots_txt
        robots_error = context.robots_error

        if robots_error:
            issues.append(
                Issue(
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
                )
            )
        elif robots_txt and "disallow: /" in robots_txt.lower():
            issues.append(
                Issue(
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
                )
            )

        if not context.sitemap_urls:
            issues.append(
                Issue(
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
                )
            )

        meta_robots = self._get_meta(analyzer, "robots")
        if meta_robots and "noindex" in meta_robots.get("content", "").lower():
            issues.append(
                Issue(
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
                )
            )

        return issues

    def _check_mobile(self, context: AuditContext) -> List[Issue]:
        analyzer = context.analyzer
        viewport = self._get_meta(analyzer, "viewport")
        issues: List[Issue] = []

        if not viewport:
            issues.append(
                Issue(
                    severity="critical",
                    category="content",
                    title="Viewport meta tag missing",
                    what="No responsive viewport meta tag detected; pages will render poorly on mobile and hurt mobile rankings.",
                    steps=[
                        'Add `<meta name="viewport" content="width=device-width, initial-scale=1">` in the `<head>`.',
                        "Ensure CSS uses responsive units (%, rem, vw) and media queries for layout.",
                        "Test across popular devices to confirm legibility without zooming.",
                    ],
                    outcome="Mobile-friendly rendering and better mobile usability signals.",
                    validation="Run Google's Mobile-Friendly Test or Lighthouse; viewport check should pass.",
                )
            )

        large_images_without_lazy = [img for img in analyzer.images if not img.get("loading")]
        if large_images_without_lazy and len(large_images_without_lazy) > 20:
            issues.append(
                Issue(
                    severity="important",
                    title="Images are not lazy-loaded for mobile",
                    what=f"{len(large_images_without_lazy)} images lack lazy-loading; mobile users download unnecessary media.",
                    steps=[
                        "Add loading='lazy' to below-the-fold images and use native lazy loading.",
                        "Ensure critical hero images remain eager to preserve LCP.",
                        "Verify responsive srcset/sizes to avoid oversized mobile assets.",
                    ],
                    outcome="Reduced mobile data usage and faster scrolling performance.",
                    validation="Inspect network waterfall on mobile throttling; offscreen images should defer loading.",
                )
            )

        return issues

    def _check_https_security(self, context: AuditContext) -> List[Issue]:
        parsed = urllib.parse.urlparse(context.final_url)
        issues: List[Issue] = []
        if parsed.scheme != "https":
            issues.append(
                Issue(
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
                )
            )

        if "strict-transport-security" not in {k.lower(): v for k, v in context.headers.items()}:
            issues.append(
                Issue(
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
                )
            )

        return issues

    def _check_schema(self, context: AuditContext) -> List[Issue]:
        analyzer = context.analyzer
        issues: List[Issue] = []
        if not analyzer.ld_json_blocks:
            issues.append(
                Issue(
                    severity="important",
                    category="content",
                    title="Structured data is missing",
                    what="No JSON-LD structured data detected; rich results eligibility is limited.",
                    steps=[
                        "Add JSON-LD schema matching the page type (Article, Product, Organization, Breadcrumb).",
                        "Validate required and recommended fields per schema.org and Google guidelines.",
                        "Keep schema in sync with on-page content to avoid manual actions.",
                    ],
                    outcome="Eligibility for rich snippets, improved CTR, and clearer entity understanding.",
                    validation="Run the URL through Google's Rich Results Test and fix any errors.",
                )
            )
        return issues

    def _check_internal_links(self, context: AuditContext) -> List[Issue]:
        analyzer = context.analyzer
        parsed = urllib.parse.urlparse(context.final_url)
        domain = parsed.netloc.lower()
        internal = 0
        external = 0
        for href in analyzer.links:
            parsed_href = urllib.parse.urlparse(href)
            if not parsed_href.netloc or parsed_href.netloc.lower() == domain:
                internal += 1
            else:
                external += 1

        issues: List[Issue] = []
        if internal < 10:
            issues.append(
                Issue(
                    severity="important",
                    category="links",
                    title="Low internal linking on the page",
                    what="Few internal links detected; link equity and crawl flow are limited.",
                    steps=[
                        "Add contextual links to related high-value pages using descriptive anchor text.",
                        "Ensure primary navigation and breadcrumbs are present and crawlable.",
                        "Surface links to orphan or deep pages that need authority.",
                    ],
                    outcome="Stronger crawl paths, better PageRank distribution, and improved topical signals.",
                    validation="Re-crawl with Screaming Frog/Sitebulb; internal link counts should increase.",
                )
            )

        if external > internal * 2 and external > 20:
            issues.append(
                Issue(
                    severity="recommended",
                    category="links",
                    title="External links dominate over internal links",
                    what=f"{external} external links vs {internal} internal links; excessive externals can dilute link equity.",
                    steps=[
                        "Prioritize internal linking to key pages before linking out.",
                        "Use rel='nofollow' or rel='sponsored' where appropriate for external references.",
                        "Group external references and keep anchors concise.",
                    ],
                    outcome="Better retention of link equity and clearer site architecture.",
                    validation="Re-run crawl and verify internal/external link ratio improves.",
                )
            )

        return issues

    def _check_duplicate_and_canonical(self, context: AuditContext) -> List[Issue]:
        analyzer = context.analyzer
        canonical = self._get_canonical(analyzer)
        issues: List[Issue] = []
        if not canonical:
            issues.append(
                Issue(
                    severity="important",
                    category="crawl",
                    title="Canonical tag missing",
                    what="No rel='canonical' found; duplicate content signals may be unclear to search engines.",
                    steps=[
                        "Add a self-referencing canonical tag in the <head> pointing to the preferred URL.",
                        "Ensure parameters or alternate variations point canonicals to the primary version.",
                        "Keep canonical URLs consistent with sitemaps and internal links.",
                    ],
                    outcome="Clear duplication signals and stable indexing of the preferred URL.",
                    validation="View source and confirm canonical is present and absolute; check in Search Console's URL Inspection.",
                )
            )

        elif canonical:
            parsed_final = urllib.parse.urlparse(context.final_url)
            parsed_canonical = urllib.parse.urlparse(canonical)
            if parsed_canonical.netloc and parsed_canonical.netloc.lower() != parsed_final.netloc.lower():
                issues.append(
                    Issue(
                        severity="important",
                        category="crawl",
                        title="Canonical points to a different host",
                        what=f"Canonical URL points to {parsed_canonical.netloc}, which differs from the page host {parsed_final.netloc}.",
                        steps=[
                            "Ensure the canonical uses the same primary domain as the page unless intentionally consolidating.",
                            "Check redirects and internal links to align with the canonical host.",
                            "Update sitemaps to match the canonical host.",
                        ],
                        outcome="Consistent canonical signals and fewer cross-domain consolidation issues.",
                        validation="Inspect the canonical tag and confirm it matches the preferred host.",
                    )
                )

        meta_robots = self._get_meta(analyzer, "robots")
        if meta_robots and "nofollow" in meta_robots.get("content", "").lower():
            issues.append(
                Issue(
                    severity="important",
                    category="crawl",
                    title="Meta robots nofollow set sitewide",
                    what="Meta robots contains 'nofollow'; internal links will not pass equity for this page.",
                    steps=[
                        "Remove 'nofollow' from meta robots where crawling is desired.",
                        "Use page-level rel='nofollow' only for specific links that need it.",
                        "Confirm server headers do not override with X-Robots-Tag: nofollow.",
                    ],
                    outcome="Internal links can pass PageRank and improve crawl flow.",
                    validation="Inspect meta robots after deploy; Search Console should show 'index, follow'.",
                )
            )

        return issues

    def _check_meta_and_headings(self, context: AuditContext) -> List[Issue]:
        analyzer = context.analyzer
        title = analyzer.title
        meta_description = self._get_meta(analyzer, "description")
        h1_tags = [h for h in analyzer.headings if h[0] == "h1"]
        issues: List[Issue] = []

        if not title:
            issues.append(
                Issue(
                    severity="critical",
                    category="content",
                    title="Title tag missing",
                    what="No <title> found; search results will lack a meaningful headline and relevance signal.",
                    steps=[
                        "Add a concise, descriptive <title> (50-60 chars) targeting the primary keyword.",
                        "Place the most important terms first and keep branding at the end.",
                        "Avoid duplicating titles across pages; keep them unique.",
                    ],
                    outcome="Stronger relevance signals and improved CTR from SERPs.",
                    validation="View source to confirm the title; check Search Console HTML improvements for duplicates.",
                )
            )
        elif len(title) < 25 or len(title) > 65:
            issues.append(
                Issue(
                    severity="important",
                    category="content",
                    title="Title length is suboptimal",
                    what=f"Title is {len(title)} characters; very short or long titles can hurt relevance and truncation.",
                    steps=[
                        "Rewrite the title to 50-60 characters with primary and secondary keywords.",
                        "Keep branding short and at the end; avoid keyword stuffing.",
                        "Align the title with the page's main heading (H1) for clarity.",
                    ],
                    outcome="Higher CTR and clearer topical targeting.",
                    validation="Preview SERP snippets and ensure the title fits without ellipsis.",
                )
            )

        if not meta_description or not meta_description.get("content"):
            issues.append(
                Issue(
                    severity="important",
                    category="content",
                    title="Meta description missing",
                    what="No meta description found; search engines may pull arbitrary text, reducing CTR.",
                    steps=[
                        "Add a 120-155 character meta description summarizing the offer and including a CTA.",
                        "Make descriptions unique per page to avoid duplication.",
                        "Reflect on-page content to avoid rewrites by search engines.",
                    ],
                    outcome="More compelling snippets and improved CTR.",
                    validation="Check SERP snippet or Fetch in Search Console; description should appear as written.",
                )
            )

        if len(h1_tags) == 0:
            issues.append(
                Issue(
                    severity="important",
                    category="content",
                    title="Missing H1 heading",
                    what="No H1 detected; the page lacks a clear top-level topic signal.",
                    steps=[
                        "Add a single, descriptive H1 that matches the primary intent of the page.",
                        "Avoid using logos or decorative text as the only H1.",
                        "Align H1 with title and query intent; keep it readable.",
                    ],
                    outcome="Clearer topical relevance and accessibility improvements.",
                    validation="Inspect rendered DOM to confirm a single H1 exists and is visible.",
                )
            )
        elif len(h1_tags) > 1:
            issues.append(
                Issue(
                    severity="recommended",
                    category="content",
                    title="Multiple H1 tags detected",
                    what=f"{len(h1_tags)} H1 tags found; multiple H1s can dilute topical focus.",
                    steps=[
                        "Keep one primary H1; demote secondary headings to H2/H3 as needed.",
                        "Ensure only visible headings use H1, not hidden elements.",
                        "Update templates to enforce a single H1 structure.",
                    ],
                    outcome="Clearer hierarchy and better topical clarity.",
                    validation="Check rendered HTML; only one H1 should remain.",
                )
            )

        hreflang_tags = [link for link in analyzer.link_tags if link.get("rel") == "alternate" and link.get("hreflang")]
        if len(hreflang_tags) > 0 and not any(link.get("href") for link in hreflang_tags if link.get("hreflang") == "x-default"):
            issues.append(
                Issue(
                    severity="recommended",
                    category="content",
                    title="hreflang missing x-default",
                    what="hreflang annotations exist but no x-default link is present.",
                    steps=[
                        "Add an x-default hreflang entry pointing to the global/default page.",
                        "Ensure reciprocal hreflang links between all language/region versions.",
                        "Validate hreflang XML sitemaps if used.",
                    ],
                    outcome="More accurate language/region targeting and fewer hreflang errors.",
                    validation="Use Search Console International Targeting report to confirm hreflang completeness.",
                )
            )

        relative_hreflang = [
            link for link in hreflang_tags if link.get("href") and not urllib.parse.urlparse(link.get("href")).scheme
        ]
        if relative_hreflang:
            issues.append(
                Issue(
                    severity="recommended",
                    category="content",
                    title="hreflang hrefs are relative",
                    what="hreflang link href values are relative; search engines expect absolute URLs.",
                    steps=[
                        "Use absolute URLs (including scheme and host) for all hreflang link tags.",
                        "Ensure each hreflang URL returns 200 and has reciprocal annotations.",
                        "Align hreflang URLs with the canonical host.",
                    ],
                    outcome="Cleaner international targeting with fewer hreflang parsing errors.",
                    validation="Re-crawl and verify hreflang links are absolute and reciprocal.",
                )
            )

        return issues

    def _get_meta(self, analyzer: SimpleHTMLAnalyzer, name: str) -> Optional[Dict[str, str]]:
        name_lower = name.lower()
        for meta in analyzer.meta_tags:
            meta_name = meta.get("name")
            if meta_name and meta_name.lower() == name_lower:
                return {k: v or "" for k, v in meta.items()}
        return None

    def _get_canonical(self, analyzer: SimpleHTMLAnalyzer) -> Optional[str]:
        for link in analyzer.link_tags:
            rel = (link.get("rel") or "").lower()
            if "canonical" in rel and link.get("href"):
                return link.get("href")
        return None
