from __future__ import annotations

import urllib.parse

from seo_agent.models import AuditContext, Issue

from .html import get_meta, get_meta_property_or_name
from .types import CheckEnv


def check_meta_and_headings(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    title = analyzer.title
    meta_description = get_meta(analyzer, "description")
    h1_tags = [h for h in analyzer.headings if h[0] == "h1"]
    issues: list[Issue] = []

    if not title:
        issues.append(
            Issue(
                id="content.title_missing",
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
                impact="high",
                effort="low",
                confidence="high",
                evidence={"title": "", "title_length": 0},
            )
        )
    elif len(title) < 25 or len(title) > 65:
        issues.append(
            Issue(
                id="content.title_length_suboptimal",
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
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"title_length": len(title)},
            )
        )

    if not meta_description or not meta_description.get("content"):
        issues.append(
            Issue(
                id="content.meta_description_missing",
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
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"meta_description": (meta_description or {}).get("content", "")},
            )
        )
    else:
        desc = meta_description.get("content", "")
        desc_len = len(desc.strip())
        if 0 < desc_len < 120:
            issues.append(
                Issue(
                    id="content.meta_description_too_short",
                    severity="important",
                    category="content",
                    title="Meta description is too short",
                    what=f"Meta description is {desc_len} characters; short snippets reduce clarity and CTR.",
                    steps=[
                        "Write a 120-155 character description summarizing the value and including a CTA.",
                        "Match on-page copy to avoid rewrites in SERP snippets.",
                        "Keep descriptions unique per page.",
                    ],
                    outcome="More compelling snippets that improve click-through rate.",
                    validation="Preview SERP snippet and ensure it fits without truncation.",
                    impact="medium",
                    effort="low",
                    confidence="high",
                    evidence={"meta_description_length": desc_len},
                )
            )
        elif desc_len > 170:
            issues.append(
                Issue(
                    id="content.meta_description_too_long",
                    severity="recommended",
                    category="content",
                    title="Meta description may be too long",
                    what=f"Meta description is {desc_len} characters; long snippets risk truncation.",
                    steps=[
                        "Trim to roughly 120-155 characters while keeping primary keywords early.",
                        "Avoid repeating the title; add a clear benefit and CTA.",
                        "Ensure uniqueness across pages.",
                    ],
                    outcome="Cleaner snippets that show fully in search results.",
                    validation="Use SERP preview to confirm the description is not truncated.",
                    impact="low",
                    effort="low",
                    confidence="high",
                    evidence={"meta_description_length": desc_len},
                )
            )

    if len(h1_tags) == 0:
        issues.append(
            Issue(
                id="content.h1_missing",
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
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"h1_count": 0},
            )
        )
    elif len(h1_tags) > 1:
        issues.append(
            Issue(
                id="content.h1_multiple",
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
                impact="low",
                effort="low",
                confidence="high",
                evidence={"h1_count": len(h1_tags)},
            )
        )

    og_title = get_meta_property_or_name(analyzer, "og:title")
    og_description = get_meta_property_or_name(analyzer, "og:description")
    twitter_card = get_meta(analyzer, "twitter:card")
    if not og_title or not og_description or not twitter_card:
        issues.append(
            Issue(
                id="content.social_meta_incomplete",
                severity="recommended",
                category="content",
                title="Social share metadata is incomplete",
                what="Missing Open Graph or Twitter card tags limits how the page renders when shared.",
                steps=[
                    "Add og:title and og:description that mirror the on-page intent.",
                    "Include twitter:card (summary or summary_large_image) and matching title/description tags.",
                    "Add og:image/twitter:image with appropriately sized media.",
                ],
                outcome="Cleaner link previews that drive higher engagement from shares.",
                validation="Share the URL in popular platforms (Slack, Facebook, X) and confirm rich previews render.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"og_title_present": bool(og_title), "og_description_present": bool(og_description), "twitter_card_present": bool(twitter_card)},
            )
        )

    images_missing_alt = [img for img in analyzer.images if not (img.get("alt") or "").strip()]
    if images_missing_alt:
        severity = "important" if len(images_missing_alt) > 10 else "recommended"
        issues.append(
            Issue(
                id="content.images_alt_missing",
                severity=severity,
                category="content",
                title="Images missing alt text",
                what=f"{len(images_missing_alt)} images lack alt text; this hurts accessibility and image SEO.",
                steps=[
                    "Add descriptive alt text for meaningful images; leave decorative images empty or use CSS backgrounds.",
                    "Ensure CMS enforces alt text on uploads.",
                    "Avoid keyword stuffing—keep alt text concise and relevant to the image.",
                ],
                outcome="Better accessibility, image indexing, and contextual relevance.",
                validation="Audit images in DevTools/SEO crawlers to confirm alt attributes are present.",
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"images_missing_alt": len(images_missing_alt), "image_count": len(analyzer.images)},
            )
        )

    hreflang_tags = [link for link in analyzer.link_tags if link.get("rel") == "alternate" and link.get("hreflang")]
    if len(hreflang_tags) > 0 and not any(link.get("href") for link in hreflang_tags if link.get("hreflang") == "x-default"):
        issues.append(
            Issue(
                id="content.hreflang_x_default_missing",
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
                impact="low",
                effort="medium",
                confidence="medium",
                evidence={"hreflang_count": len(hreflang_tags)},
            )
        )

    relative_hreflang = [
        link for link in hreflang_tags if link.get("href") and not urllib.parse.urlparse(link.get("href")).scheme
    ]
    if relative_hreflang:
        issues.append(
            Issue(
                id="content.hreflang_relative_urls",
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
                impact="low",
                effort="low",
                confidence="high",
                evidence={"relative_hreflang_count": len(relative_hreflang)},
            )
        )

    return issues
