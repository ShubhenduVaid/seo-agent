from __future__ import annotations

import re

from seo_agent.models import AuditContext, Issue

from .types import CheckEnv

_LANG_RE = re.compile(r"^[a-z]{2,3}(-[a-z0-9]{2,8})*$", re.IGNORECASE)


def check_document_metadata(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    issues: list[Issue] = []

    lang = (context.analyzer.html_attrs.get("lang") or "").strip()
    if not lang:
        issues.append(
            Issue(
                id="content.lang_missing",
                severity="recommended",
                category="content",
                title="HTML lang attribute missing",
                what="No `lang` attribute detected on the `<html>` element; language targeting and accessibility signals are weaker.",
                steps=[
                    "Set `<html lang=\"...\">` to the primary language of the page (e.g., en, en-US, fr).",
                    "Ensure language variants use correct BCP 47 language tags across templates.",
                    "If the site is multilingual, align `lang` with hreflang annotations per page.",
                ],
                outcome="Clearer language targeting for search engines and improved accessibility tooling.",
                validation="View source and confirm `<html lang=\"...\">` is present and matches the page language.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"lang": lang},
            )
        )
    elif not _LANG_RE.match(lang):
        issues.append(
            Issue(
                id="content.lang_invalid",
                severity="recommended",
                category="content",
                title="HTML lang attribute looks invalid",
                what=f"`<html lang>` value \"{lang}\" does not look like a valid language tag (expected BCP 47 such as en or en-US).",
                steps=[
                    "Use a valid BCP 47 language tag (e.g., en, en-US, pt-BR).",
                    "Avoid underscores; use hyphens for language-region (e.g., en-US).",
                    "Keep the tag consistent across templates for each locale.",
                ],
                outcome="More accurate language signals for indexing and accessibility.",
                validation="Validate that `<html lang>` uses a standard tag and matches the rendered language.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"lang": lang},
            )
        )

    if not _has_charset_hint(context):
        issues.append(
            Issue(
                id="content.charset_missing",
                severity="recommended",
                category="content",
                title="Character encoding hint missing",
                what="No charset was detected in headers or HTML meta tags; encoding ambiguity can cause rendering/indexing edge cases.",
                steps=[
                    "Ensure the HTTP `Content-Type` header includes a charset (e.g., `text/html; charset=utf-8`).",
                    "Add `<meta charset=\"utf-8\">` early in `<head>`.",
                    "Avoid mixed encodings; keep templates consistently UTF-8.",
                ],
                outcome="More consistent rendering and text processing for crawlers and browsers.",
                validation="Check response headers and HTML source for charset hints (prefer UTF-8).",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"content_type": context.content_type},
            )
        )

    return issues


def _has_charset_hint(context: AuditContext) -> bool:
    if "charset=" in (context.content_type or "").lower():
        return True
    for meta in context.analyzer.meta_tags:
        charset = (meta.get("charset") or "").strip()
        if charset:
            return True
        http_equiv = (meta.get("http-equiv") or "").strip().lower()
        content = (meta.get("content") or "").strip().lower()
        if http_equiv == "content-type" and "charset=" in content:
            return True
    return False

