import unittest

from seo_agent.analyzer import SimpleHTMLAnalyzer
from seo_agent.audit import SeoAuditAgent
from seo_agent.models import AuditContext
from seo_agent.network import normalize_url
from seo_agent.reporting import render_unreachable


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


if __name__ == "__main__":
    unittest.main()
