from __future__ import annotations

import urllib.parse
from typing import List

from seo_agent.models import AuditContext, Issue

from .html import get_meta
from .types import CheckEnv


def check_speed(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    html_size_kb = len(context.html.encode("utf-8")) / 1024
    response_time_ms = context.fetch_duration_ms
    script_count = len(analyzer.scripts)
    blocking_scripts = [s for s in analyzer.scripts if not s.get("async") and not s.get("defer")]
    image_count = len(analyzer.images)
    missing_img_sizes = [img for img in analyzer.images if not img.get("width") or not img.get("height")]
    link_hints = [link for link in analyzer.link_tags if link.get("rel") in {"preload", "prefetch"}]
    headers_lower = {k.lower(): v for k, v in context.headers.items()}
    cache_control = headers_lower.get("cache-control", "")
    content_encoding = headers_lower.get("content-encoding", "")
    etag = headers_lower.get("etag")
    last_modified = headers_lower.get("last-modified")

    issues: list[Issue] = []
    if response_time_ms > 5000:
        issues.append(
            Issue(
                id="performance.response_time_very_high",
                severity="critical",
                category="performance",
                title="Response time is very high",
                what=f"HTML response took ~{response_time_ms} ms; slow TTFB harms crawl budget and Core Web Vitals.",
                steps=[
                    "Profile server/application for slow queries and heavy middleware.",
                    "Enable CDN edge caching for the HTML where possible.",
                    "Reduce server work before first byte (DB optimizations, caching, lighter middleware).",
                ],
                outcome="Lower TTFB and faster initial render, improving crawl efficiency and UX.",
                validation="Measure TTFB in WebPageTest/Lighthouse; aim for < 800 ms on mobile throttling.",
                impact="high",
                effort="high",
                confidence="medium",
                evidence={"response_time_ms": response_time_ms},
            )
        )
    elif response_time_ms > 2500:
        issues.append(
            Issue(
                id="performance.response_time_high",
                severity="important",
                category="performance",
                title="Response time could be improved",
                what=f"HTML response took ~{response_time_ms} ms; slower TTFB delays rendering and indexing.",
                steps=[
                    "Add caching at the app or CDN layer for anonymous traffic.",
                    "Optimize DB calls and reduce server-side rendering overhead.",
                    "Keep redirects minimal so first byte is served from the primary origin quickly.",
                ],
                outcome="Faster initial response and better Web Vitals.",
                validation="Re-test TTFB under mobile throttling; target < 1s.",
                impact="medium",
                effort="medium",
                confidence="medium",
                evidence={"response_time_ms": response_time_ms},
            )
        )

    if html_size_kb > 1600:
        issues.append(
            Issue(
                id="performance.page_weight_heavy",
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
                impact="high",
                effort="high",
                confidence="high",
                evidence={"html_size_kb": int(html_size_kb)},
            )
        )
    elif html_size_kb > 900:
        issues.append(
            Issue(
                id="performance.page_weight_high",
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
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"html_size_kb": int(html_size_kb)},
            )
        )

    if script_count > 40 or len(blocking_scripts) > 15:
        issues.append(
            Issue(
                id="performance.render_blocking_scripts_too_many",
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
                impact="high",
                effort="medium",
                confidence="high",
                evidence={"script_count": script_count, "blocking_script_count": len(blocking_scripts)},
            )
        )
    elif script_count > 25:
        issues.append(
            Issue(
                id="performance.script_count_high",
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
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"script_count": script_count},
            )
        )

    if missing_img_sizes:
        issues.append(
            Issue(
                id="performance.images_missing_dimensions",
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
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"images_missing_dimensions": len(missing_img_sizes), "image_count": image_count},
            )
        )

    if image_count > 80:
        issues.append(
            Issue(
                id="performance.image_count_high",
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
                impact="low",
                effort="medium",
                confidence="high",
                evidence={"image_count": image_count},
            )
        )

    if html_size_kb > 2000 and not link_hints:
        issues.append(
            Issue(
                id="performance.resource_hints_missing",
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
                impact="low",
                effort="low",
                confidence="medium",
                evidence={"html_size_kb": int(html_size_kb)},
            )
        )

    if not cache_control:
        issues.append(
            Issue(
                id="performance.cache_control_missing",
                severity="recommended",
                category="performance",
                title="Cache-Control header missing",
                what="No Cache-Control header detected; browsers and CDNs cannot reuse the HTML effectively.",
                steps=[
                    "Set sensible Cache-Control for HTML (e.g., short max-age with revalidation) and longer for static assets.",
                    "Use ETag/Last-Modified to allow conditional requests.",
                    "Verify caching rules in CDN/origin configs.",
                ],
                outcome="Better repeat-visit performance and reduced server load.",
                validation="Check response headers for Cache-Control; confirm hits/misses in CDN logs.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"cache_control": cache_control},
            )
        )
    if not etag and not last_modified:
        issues.append(
            Issue(
                id="performance.validators_missing",
                severity="recommended",
                category="performance",
                title="No validators for revalidation",
                what="Neither ETag nor Last-Modified headers were found; conditional GETs cannot validate cached copies.",
                steps=[
                    "Enable ETag or Last-Modified on HTML responses.",
                    "Ensure proxies/CDNs forward validation headers.",
                    "Test conditional requests to confirm 304 responses when content is unchanged.",
                ],
                outcome="Lower bandwidth and faster repeat views via 304 responses.",
                validation="Send repeated requests with If-None-Match/If-Modified-Since; expect 304 when unchanged.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"etag_present": bool(etag), "last_modified_present": bool(last_modified)},
            )
        )
    if context.content_size > 200 * 1024 and not content_encoding:
        issues.append(
            Issue(
                id="performance.html_compression_missing",
                severity="recommended",
                category="performance",
                title="Compression not detected for large HTML",
                what=f"Document is ~{int(context.content_size/1024)} KB and no compression header (gzip/br) was seen.",
                steps=[
                    "Enable gzip or Brotli compression for HTML and JSON at the CDN/origin.",
                    "Confirm proxies are not stripping Content-Encoding.",
                    "Monitor payload sizes after enabling compression.",
                ],
                outcome="Smaller transfers and faster first render, especially on mobile networks.",
                validation="Check response headers for Content-Encoding and compare transfer sizes before/after.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"content_size_bytes": context.content_size, "content_encoding": content_encoding},
            )
        )

    return issues


def check_assets(context: AuditContext, env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    domain = urllib.parse.urlparse(context.final_url).netloc.lower()
    resource_hrefs: List[str] = []
    for script in analyzer.scripts:
        src = script.get("src")
        if src:
            resource_hrefs.append(src)
    for link in analyzer.link_tags:
        rel = (link.get("rel") or "").lower()
        href = link.get("href")
        if rel == "stylesheet" and href:
            resource_hrefs.append(href)

    resources = _collect_same_host_links(context.final_url, resource_hrefs, domain)
    if not resources:
        return []

    checked = []
    for url in resources[:6]:
        res = env.head(url, verify_ssl=env.verify_ssl, timeout=env.timeout, user_agent=env.user_agent)
        checked.append((url, res))

    no_cache: List[str] = []
    no_compress: List[str] = []
    for url, res in checked:
        if res.error or not res.headers:
            continue
        headers_lower = {k.lower(): v for k, v in res.headers.items()}
        if "cache-control" not in headers_lower:
            no_cache.append(url)
        content_length = 0
        try:
            content_length = int(headers_lower.get("content-length", "0"))
        except ValueError:
            content_length = 0
        if "content-encoding" not in headers_lower and content_length > 30_000:
            no_compress.append(url)

    issues: list[Issue] = []
    if no_cache:
        severity = "important" if len(no_cache) >= 3 else "recommended"
        sample = ", ".join(no_cache[:3])
        issues.append(
            Issue(
                id="performance.static_assets_cache_control_missing",
                severity=severity,
                category="performance",
                title="Static assets lack caching headers",
                what=f"{len(no_cache)} script/style asset(s) missing Cache-Control; repeat visits will redownload them. Examples: {sample}",
                steps=[
                    "Add long-lived Cache-Control with immutable or strong validators for JS/CSS assets.",
                    "Include ETag/Last-Modified so clients can revalidate quickly.",
                    "Ensure CDN/origin does not strip caching headers for static files.",
                ],
                outcome="Faster repeat visits and lower bandwidth for scripts/styles.",
                validation="Re-fetch assets and confirm Cache-Control is present with a suitable max-age.",
                impact="medium",
                effort="medium",
                confidence="medium",
                evidence={"missing_cache_control_count": len(no_cache), "sample_urls": no_cache[:3]},
            )
        )
    if no_compress:
        severity = "important" if len(no_compress) >= 2 else "recommended"
        sample = ", ".join(no_compress[:3])
        issues.append(
            Issue(
                id="performance.static_assets_compression_missing",
                severity=severity,
                category="performance",
                title="Large assets are not compressed",
                what=f"{len(no_compress)} large JS/CSS asset(s) lack gzip/br compression. Examples: {sample}",
                steps=[
                    "Enable gzip or Brotli compression for text-based static assets at CDN/origin.",
                    "Confirm Content-Encoding is preserved through proxies.",
                    "Monitor asset transfer sizes before and after enabling compression.",
                ],
                outcome="Smaller downloads and faster rendering for script/style payloads.",
                validation="Check asset response headers for Content-Encoding and reduced transfer size.",
                impact="medium",
                effort="medium",
                confidence="medium",
                evidence={"missing_compression_count": len(no_compress), "sample_urls": no_compress[:3]},
            )
        )
    return issues


def check_mobile(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    viewport = get_meta(analyzer, "viewport")
    issues: list[Issue] = []

    if not viewport:
        issues.append(
            Issue(
                id="content.viewport_missing",
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
                impact="high",
                effort="low",
                confidence="high",
                evidence={"present": False},
            )
        )

    large_images_without_lazy = [img for img in analyzer.images if not img.get("loading")]
    if large_images_without_lazy and len(large_images_without_lazy) > 20:
        issues.append(
            Issue(
                id="performance.images_lazy_loading_missing",
                severity="important",
                category="performance",
                title="Images are not lazy-loaded for mobile",
                what=f"{len(large_images_without_lazy)} images lack lazy-loading; mobile users download unnecessary media.",
                steps=[
                    "Add loading='lazy' to below-the-fold images and use native lazy loading.",
                    "Ensure critical hero images remain eager to preserve LCP.",
                    "Verify responsive srcset/sizes to avoid oversized mobile assets.",
                ],
                outcome="Reduced mobile data usage and faster scrolling performance.",
                validation="Inspect network waterfall on mobile throttling; offscreen images should defer loading.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"images_without_loading_attr": len(large_images_without_lazy)},
            )
        )

    return issues


def _collect_same_host_links(base_url: str, hrefs: List[str], domain: str) -> List[str]:
    collected: List[str] = []
    for href in hrefs:
        resolved = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme not in {"http", "https"}:
            continue
        if parsed.netloc.lower() != domain:
            continue
        normalized = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        if normalized not in collected:
            collected.append(normalized)
    return collected
