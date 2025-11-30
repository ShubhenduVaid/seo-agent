import unittest

from seo_agent.analyzer import SimpleHTMLAnalyzer
from seo_agent.audit import SeoAuditAgent
from seo_agent.models import AuditContext
from seo_agent.network import normalize_url
from seo_agent.reporting import render_unreachable, render_report


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


def _build_context(
    url: str = "https://example.com",
    final: str = "https://example.com",
    html: str | None = None,
    headers: dict | None = None,
) -> AuditContext:
    sample_html = html or "<html><head><title>Test</title></head><body><h1>Hi</h1></body></html>"
    analyzer = SimpleHTMLAnalyzer()
    analyzer.feed(sample_html)
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
    )


if __name__ == "__main__":
    unittest.main()
