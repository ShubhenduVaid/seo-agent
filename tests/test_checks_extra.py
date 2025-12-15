import unittest

from seo_agent.analyzer import SimpleHTMLAnalyzer
from seo_agent.checks.broken_links import check_broken_internal_links
from seo_agent.checks.canonical import check_canonical_target, check_duplicate_and_canonical
from seo_agent.checks.crawlability import check_crawlability
from seo_agent.checks.document import check_document_metadata
from seo_agent.checks.fetch import check_html_truncation
from seo_agent.checks.html import (
    extract_schema_types,
    get_canonical,
    get_canonicals,
    get_meta,
    get_meta_property_or_name,
)
from seo_agent.checks.links import check_internal_links
from seo_agent.checks.types import CheckEnv
from seo_agent.models import AuditContext, HeadResult


def _context(html: str, final_url: str = "https://example.com/") -> AuditContext:
    analyzer = SimpleHTMLAnalyzer()
    analyzer.feed(html)
    return AuditContext(
        url=final_url,
        final_url=final_url,
        status_code=200,
        html=html,
        headers={},
        robots_txt="User-agent: *\nDisallow:",
        robots_error=None,
        sitemap_urls=[],
        analyzer=analyzer,
        content_type="text/html; charset=utf-8",
    )


class ChecksExtraTests(unittest.TestCase):
    def test_html_helpers_extract_meta_and_canonicals_and_schema_types(self) -> None:
        html = """
        <html lang="en"><head>
          <meta name="Description" content="hello">
          <meta property="og:title" content="OG">
          <link rel="canonical" href="https://example.com/a">
          <link rel="canonical alternate" href="https://example.com/b">
        </head><body></body></html>
        """
        ctx = _context(html)
        analyzer = ctx.analyzer
        self.assertEqual(get_meta(analyzer, "description")["content"], "hello")  # type: ignore[index]
        self.assertEqual(get_meta_property_or_name(analyzer, "og:title")["content"], "OG")  # type: ignore[index]
        self.assertEqual(get_canonical(analyzer), "https://example.com/a")
        self.assertEqual(get_canonicals(analyzer)[:2], ["https://example.com/a", "https://example.com/b"])

        schema = {"@type": ["WebPage", "Thing"], "@graph": [{"@type": "BreadcrumbList"}, {"@type": "Organization"}]}
        self.assertEqual(extract_schema_types(schema), ["WebPage", "Thing", "BreadcrumbList", "Organization"])

    def test_check_html_truncation_flags_truncated_fetch(self) -> None:
        ctx = _context("<html><head></head><body></body></html>")
        ctx.truncated = True
        issues = check_html_truncation(ctx, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        self.assertTrue(any(i.id == "fetch.html_truncated" for i in issues))

    def test_check_document_metadata_lang_and_charset_detection(self) -> None:
        missing_lang = _context("<html><head></head><body></body></html>", final_url="https://example.com/")
        issues = check_document_metadata(missing_lang, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        ids = {i.id for i in issues}
        self.assertIn("content.lang_missing", ids)

        invalid_lang = _context("<html lang=\"en_US\"><head></head><body></body></html>")
        issues = check_document_metadata(invalid_lang, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        self.assertIn("content.lang_invalid", {i.id for i in issues})

        charset_header = _context("<html lang=\"en\"><head></head><body></body></html>")
        charset_header.content_type = "text/html; charset=utf-8"
        issues = check_document_metadata(charset_header, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        self.assertFalse(any(i.id == "content.charset_missing" for i in issues))

        meta_charset = _context("<html lang=\"en\"><head><meta charset=\"utf-8\"></head><body></body></html>")
        issues = check_document_metadata(meta_charset, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        self.assertFalse(any(i.id == "content.charset_missing" for i in issues))

        http_equiv = _context(
            "<html lang=\"en\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"></head><body></body></html>"
        )
        issues = check_document_metadata(http_equiv, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        self.assertFalse(any(i.id == "content.charset_missing" for i in issues))

    def test_check_internal_links_flags_external_dominance(self) -> None:
        externals = "".join(f'<a href=\"https://ext{i}.com\">x</a>' for i in range(25))
        internals = "".join(f'<a href=\"/p{i}\">i</a>' for i in range(5))
        ctx = _context(f"<html><head><title>T</title></head><body>{internals}{externals}</body></html>")
        issues = check_internal_links(ctx, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        self.assertTrue(any(i.id == "links.external_links_dominate" for i in issues))

    def test_check_crawlability_flags_meta_robots_noindex(self) -> None:
        ctx = _context("<html><head><meta name=\"robots\" content=\"noindex\"></head><body></body></html>")
        issues = check_crawlability(ctx, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        self.assertTrue(any(i.id == "crawl.meta_robots_noindex" for i in issues))

    def test_check_duplicate_and_canonical_flags_multiple_and_nofollow(self) -> None:
        html = """
        <html><head>
          <link rel="canonical" href="https://example.com/a">
          <link rel="canonical" href="https://example.com/b">
          <meta name="robots" content="nofollow">
        </head><body></body></html>
        """
        ctx = _context(html)
        issues = check_duplicate_and_canonical(ctx, CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=lambda *_a, **_k: HeadResult({}, 200, None)))
        ids = {i.id for i in issues}
        self.assertIn("crawl.canonical_multiple", ids)
        self.assertIn("crawl.meta_robots_nofollow", ids)

    def test_check_canonical_target_detects_errors_and_redirects(self) -> None:
        html = "<html><head><link rel=\"canonical\" href=\"/target\"></head><body></body></html>"
        ctx = _context(html, final_url="https://example.com/page")

        def head(url: str, **_kwargs) -> HeadResult:
            if url.endswith("/target-404"):
                return HeadResult(headers={}, status_code=404, error=None)
            if url.endswith("/target-302"):
                return HeadResult(headers={}, status_code=302, error=None)
            if url.endswith("/target-405"):
                return HeadResult(headers={}, status_code=405, error=None)
            if url.endswith("/target-error"):
                return HeadResult(headers={}, status_code=0, error="boom")
            return HeadResult(headers={}, status_code=200, error=None)

        env = CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=head)

        # Switch canonical hrefs to hit each branch.
        for href, expected_id in [
            ("/target-404", "crawl.canonical_target_error"),
            ("/target-302", "crawl.canonical_target_redirect"),
        ]:
            ctx.analyzer.link_tags = [{"rel": "canonical", "href": href}]
            issues = check_canonical_target(ctx, env)
            self.assertEqual([i.id for i in issues], [expected_id])

        ctx.analyzer.link_tags = [{"rel": "canonical", "href": "/target-405"}]
        self.assertEqual(check_canonical_target(ctx, env), [])
        ctx.analyzer.link_tags = [{"rel": "canonical", "href": "/target-error"}]
        self.assertEqual(check_canonical_target(ctx, env), [])
        ctx.analyzer.link_tags = [{"rel": "canonical", "href": "/target"}]
        self.assertEqual(check_canonical_target(ctx, env), [])

    def test_check_broken_internal_links_is_bounded_and_reports_examples(self) -> None:
        html = """
        <html><head><title>T</title></head><body>
          <a href="/ok">OK</a>
          <a href="/missing">Missing</a>
          <a href="/method">Method</a>
          <a href="/error">Error</a>
          <a href="mailto:test@example.com">Mail</a>
          <a href="https://external.com/">External</a>
        </body></html>
        """
        ctx = _context(html)

        def head(url: str, **_kwargs) -> HeadResult:
            if url.endswith("/missing"):
                return HeadResult(headers={}, status_code=404, error=None)
            if url.endswith("/method"):
                return HeadResult(headers={}, status_code=405, error=None)
            if url.endswith("/error"):
                return HeadResult(headers={}, status_code=0, error="timeout")
            return HeadResult(headers={}, status_code=200, error=None)

        env = CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=head, check_links=True, link_check_limit_per_page=10)
        issues = check_broken_internal_links(ctx, env)
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.id, "crawl.internal_links_broken")
        self.assertIn("Examples:", issue.what)
        self.assertIn("broken", issue.evidence)

        env_off = CheckEnv(verify_ssl=True, user_agent="", timeout=1, head=head, check_links=False, link_check_limit_per_page=10)
        self.assertEqual(check_broken_internal_links(ctx, env_off), [])
