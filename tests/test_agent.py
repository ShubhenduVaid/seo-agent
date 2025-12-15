import json
import unittest

from typing import Optional

from seo_agent.analyzer import SimpleHTMLAnalyzer
from seo_agent.audit import SeoAuditAgent
from seo_agent.baseline import build_baseline, diff_baselines
from seo_agent.models import AuditContext, FetchResult, HeadResult, Issue, RobotsResult
from seo_agent.network import normalize_url
from seo_agent.reporting import render_unreachable, render_report

StrOrNone = Optional[str]


class SeoAgentTests(unittest.TestCase):
    def test_normalize_url_adds_https(self) -> None:
        self.assertEqual(normalize_url("example.com/page"), "https://example.com/page")

    def test_collect_issues_flags_missing_core_elements(self) -> None:
        sample_html = """
        <html>
          <head>
            <meta name="description" content="">
            <link rel="alternate" hreflang="fr" href="https://example.com/fr">
          </head>
          <body>
            <h1>Sample Heading</h1>
            <a href="https://external.com">External</a>
          </body>
        </html>
        """
        analyzer = SimpleHTMLAnalyzer()
        analyzer.feed(sample_html)
        context = AuditContext(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            html=sample_html,
            headers={},
            robots_txt=None,
            robots_error="404 not found",
            sitemap_urls=[],
            analyzer=analyzer,
        )
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}

        self.assertIn("Title tag missing", titles)
        self.assertIn("Meta description missing", titles)
        self.assertIn("Structured data is missing", titles)
        self.assertIn("Canonical tag missing", titles)
        self.assertIn("Low internal linking on the page", titles)
        self.assertIn("XML sitemap not advertised", titles)
        self.assertIn("robots.txt is unreachable", titles)

    def test_render_unreachable_mentions_error(self) -> None:
        message = render_unreachable("https://example.com", "traffic", "timeout")
        self.assertIn("timeout", message)
        self.assertIn("Could not fetch https://example.com", message)

    def test_render_report_json_format(self) -> None:
        sample_html = "<html><head><title>Test</title></head><body><h1>Hi</h1></body></html>"
        analyzer = SimpleHTMLAnalyzer()
        analyzer.feed(sample_html)
        context = AuditContext(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            html=sample_html,
            headers={},
            robots_txt=None,
            robots_error=None,
            sitemap_urls=[],
            analyzer=analyzer,
        )
        agent = SeoAuditAgent(output_format="json")
        issues = agent._collect_issues(context)
        output = render_report(context, "goal", issues, fmt="json")
        self.assertTrue(output.startswith("{"))
        self.assertIn('"critical"', output)
        self.assertIn('"overall"', output)

    def test_status_check_flags_server_error(self) -> None:
        sample_html = "<html><head><title>Test</title></head><body></body></html>"
        analyzer = SimpleHTMLAnalyzer()
        analyzer.feed(sample_html)
        context = AuditContext(
            url="https://example.com",
            final_url="https://example.com",
            status_code=503,
            html=sample_html,
            headers={},
            robots_txt=None,
            robots_error=None,
            sitemap_urls=[],
            analyzer=analyzer,
        )
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertTrue(any(t.startswith("Page returns 503") for t in titles))
        self.assertTrue(all(hasattr(issue, "category") for issue in issues))

    def test_redirect_check_flags_redirect(self) -> None:
        context = _build_context(url="https://a.com/page", final="https://b.com/page")
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertIn("URL redirects to a different location", titles)

    def test_header_checks_x_robots(self) -> None:
        context = _build_context(headers={"X-Robots-Tag": "noindex, nofollow"})
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertIn("X-Robots-Tag blocks indexing", titles)

    def test_canonical_cross_host(self) -> None:
        html = """
        <html><head>
        <link rel="canonical" href="https://other.com/page">
        <title>Test</title>
        </head><body><h1>Hi</h1></body></html>
        """
        context = _build_context(final="https://example.com/page", html=html)
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertIn("Canonical points to a different host", titles)

    def test_resource_hints_missing_for_heavy_page(self) -> None:
        body = "a" * (2_050 * 1024)  # ~2MB
        html = f"<html><head><title>Test</title></head><body>{body}</body></html>"
        context = _build_context(html=html)
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertIn("No resource hints for heavy pages", titles)

    def test_slow_response_flagged(self) -> None:
        context = _build_context(fetch_duration_ms=6000)
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertIn("Response time is very high", titles)

    def test_meta_description_length_flagged(self) -> None:
        html = """
        <html><head>
        <title>Test</title>
        <meta name="description" content="Too short">
        </head><body><h1>Hi</h1></body></html>
        """
        context = _build_context(html=html)
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertIn("Meta description is too short", titles)

    def test_invalid_structured_data_flagged(self) -> None:
        html = """
        <html><head><title>Test</title>
        <script type="application/ld+json">{invalid json</script>
        </head><body><h1>Hi</h1></body></html>
        """
        context = _build_context(html=html)
        agent = SeoAuditAgent()
        issues = agent._collect_issues(context)
        titles = {issue.title for issue in issues}
        self.assertIn("Structured data could not be parsed", titles)

    def test_crawl_collects_additional_pages(self) -> None:
        pages = {
            "https://example.com": """
            <html><head><title>Root</title></head>
            <body><h1>Hi</h1><a href="/p2">Next</a></body></html>
            """,
            "https://example.com/p2": "<html><head></head><body><h1>Subpage</h1></body></html>",
        }
        fetcher = _make_fetcher(pages)
        agent = SeoAuditAgent(fetch_func=fetcher, robots_loader=_stub_robots_loader)
        _report, issues = agent.audit_with_details("https://example.com", "goal", crawl_depth=1, crawl_limit=2)
        self.assertTrue(any(issue.page.endswith("/p2") and issue.title == "Title tag missing" for issue in issues))

    def test_asset_head_checks_cache(self) -> None:
        html = """
        <html><head><title>Test</title><link rel="stylesheet" href="/style.css"></head>
        <body><h1>Hi</h1><script src="/app.js"></script></body></html>
        """
        fetcher = _make_fetcher({"https://example.com": html})
        head_responses = {
            "https://example.com/app.js": {"content-length": "40000"},
            "https://example.com/style.css": {"cache-control": "max-age=31536000", "content-length": "50000"},
        }
        head_stub = _make_head(head_responses)
        agent = SeoAuditAgent(fetch_func=fetcher, head_func=head_stub, robots_loader=_stub_robots_loader)
        _report, issues = agent.audit_with_details("https://example.com", "goal")
        titles = {issue.title for issue in issues}
        self.assertIn("Static assets lack caching headers", titles)
        self.assertIn("Large assets are not compressed", titles)

    def test_robots_blocks_crawl(self) -> None:
        html = """
        <html><head><title>Root</title></head>
        <body><h1>Hi</h1><a href="/blocked/page">Blocked</a></body></html>
        """
        fetcher = _make_fetcher({"https://example.com": html})
        robots_loader = _make_robots_loader("User-agent: *\nDisallow: /blocked")
        agent = SeoAuditAgent(fetch_func=fetcher, robots_loader=robots_loader)
        _report, issues = agent.audit_with_details("https://example.com", "goal", crawl_depth=1, crawl_limit=2)
        self.assertFalse(any("/blocked" in issue.page for issue in issues))

    def test_crawl_summary_duplicates(self) -> None:
        root = """
        <html><head><title>Root</title><meta name="description" content="Same desc"></head>
        <body><h1>Hi</h1><a href="/p2">P2</a><a href="/p3">P3</a></body></html>
        """
        dup_page = """
        <html><head><title>Shared Title</title><meta name="description" content="Same desc"></head>
        <body><h1>Hi</h1></body></html>
        """
        fetcher = _make_fetcher({"https://example.com": root, "https://example.com/p2": dup_page, "https://example.com/p3": dup_page})
        agent = SeoAuditAgent(output_format="json", fetch_func=fetcher, robots_loader=_stub_robots_loader)
        report, _ = agent.audit_with_details("https://example.com", "traffic growth", crawl_depth=1, crawl_limit=3)
        data = json.loads(report)
        summary = data.get("crawl_summary", {})
        self.assertGreaterEqual(summary.get("pages_crawled", 0), 2)
        self.assertTrue(summary.get("duplicate_titles"))
        self.assertTrue(summary.get("duplicate_descriptions"))

    def test_baseline_diff_detects_new_and_fixed(self) -> None:
        issue_a = _make_issue("content.title_missing", "critical", "Title tag missing", page="https://example.com/")
        issue_b = _make_issue("security.hsts_missing", "recommended", "HSTS header not detected", page="https://example.com/")
        baseline = build_baseline("https://example.com", "goal", [issue_a])
        current = build_baseline("https://example.com", "goal", [issue_b])
        diff = diff_baselines(baseline, current)
        summary = diff.get("summary", {})
        self.assertEqual(summary.get("fixed"), 1)
        self.assertEqual(summary.get("new"), 1)

    def test_make_fetcher_returns_error_for_missing_page(self) -> None:
        fetcher = _make_fetcher({"https://example.com": "<html><body></body></html>"})
        result = fetcher("https://example.com/missing")
        self.assertEqual(result.status_code, 404)
        self.assertIsNotNone(result.error)


def _build_context(
    url: str = "https://example.com",
    final: str = "https://example.com",
    html: StrOrNone = None,
    headers: dict = None,
    fetch_duration_ms: int = 0,
    content_size: int = 0,
) -> AuditContext:
    sample_html = html or "<html><head><title>Test</title></head><body><h1>Hi</h1></body></html>"
    analyzer = SimpleHTMLAnalyzer()
    analyzer.feed(sample_html)
    size = content_size or len(sample_html.encode("utf-8"))
    return AuditContext(
        url=url,
        final_url=final,
        status_code=200,
        html=sample_html,
        headers=headers or {},
        robots_txt=None,
        robots_error=None,
        sitemap_urls=[],
        analyzer=analyzer,
        fetch_duration_ms=fetch_duration_ms,
        content_size=size,
    )


def _make_fetcher(pages: dict) -> object:
    def _fetch(url: str, verify_ssl: bool = True, timeout: int = 12, user_agent: str = "") -> FetchResult:
        normalized = normalize_url(url)
        html = pages.get(normalized)
        if html is None:
            return FetchResult(body="", final_url=normalized, headers={}, status_code=404, error="not found", duration_ms=5, content_size=0)
        size = len(html.encode("utf-8"))
        return FetchResult(body=html, final_url=normalized, headers={}, status_code=200, error=None, duration_ms=15, content_size=size)

    return _fetch


def _make_head(responses: dict) -> object:
    def _head(url: str, verify_ssl: bool = True, timeout: int = 12, user_agent: str = "") -> HeadResult:
        headers = responses.get(url, {})
        return HeadResult(headers=headers, status_code=200, error=None, duration_ms=5)

    return _head


def _stub_robots_loader(url: str, verify_ssl: bool = True, timeout: int = 12, user_agent: str = "") -> RobotsResult:
    return RobotsResult(content="", error=None, sitemap_urls=[])


def _make_robots_loader(content: str) -> object:
    def _loader(url: str, verify_ssl: bool = True, timeout: int = 12, user_agent: str = "") -> RobotsResult:
        return RobotsResult(content=content, error=None, sitemap_urls=[])

    return _loader


def _make_issue(issue_id: str, severity: str, title: str, page: str) -> Issue:
    return Issue(
        id=issue_id,
        severity=severity,
        title=title,
        what="",
        steps=[],
        outcome="",
        validation="",
        page=page,
    )
