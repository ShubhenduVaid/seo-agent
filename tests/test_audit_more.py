import unittest
from unittest.mock import patch

from seo_agent.analyzer import SimpleHTMLAnalyzer
from seo_agent.audit import SeoAuditAgent
from seo_agent.models import AuditContext, FetchResult, Issue, RobotsResult


def _fetch_ok(url: str, **_kwargs) -> FetchResult:
    html = "<html><head><title>T</title></head><body><h1>H</h1><a href=\"/p2\">p2</a></body></html>"
    return FetchResult(
        body=html,
        final_url=url,
        headers={"Content-Type": "text/html; charset=utf-8"},
        status_code=200,
        error=None,
        duration_ms=5,
        content_size=len(html.encode("utf-8")),
        content_type="text/html; charset=utf-8",
        truncated=False,
    )


def _robots_loader(url: str, **_kwargs) -> RobotsResult:
    return RobotsResult(content="User-agent: *\nDisallow:", error=None, sitemap_urls=[])


class AuditMoreTests(unittest.TestCase):
    def test_audit_returns_report_string(self) -> None:
        agent = SeoAuditAgent(fetch_func=_fetch_ok, robots_loader=_robots_loader)
        report = agent.audit("https://example.com/", "goal")
        self.assertIn("URL audited:", report)

    def test_audit_with_details_invalid_scheme_renders_unreachable(self) -> None:
        agent = SeoAuditAgent(fetch_func=_fetch_ok, robots_loader=_robots_loader)
        report, issues = agent.audit_with_details("ftp://example.com", "goal")
        self.assertIn("Only http:// and https:// URLs are supported", report)
        self.assertEqual(issues, [])

    def test_audit_with_details_fetch_error_renders_unreachable(self) -> None:
        def fetch_error(url: str, **_kwargs) -> FetchResult:
            return FetchResult(body="", final_url=url, headers={}, status_code=0, error="timeout", duration_ms=1, content_size=0)

        agent = SeoAuditAgent(fetch_func=fetch_error, robots_loader=_robots_loader)
        report, issues = agent.audit_with_details("https://example.com/", "goal")
        self.assertIn("timeout", report)
        self.assertEqual(issues, [])

    def test_collect_same_host_links_filters_scheme_and_domain(self) -> None:
        agent = SeoAuditAgent(fetch_func=_fetch_ok, robots_loader=_robots_loader)
        hrefs = ["mailto:test@example.com", "https://other.com/x", "/ok", "https://example.com/y"]
        links = agent._collect_same_host_links("https://example.com/base", hrefs, "example.com")
        self.assertIn("https://example.com/ok", links)
        self.assertIn("https://example.com/y", links)
        self.assertFalse(any("mailto:" in u for u in links))
        self.assertFalse(any("other.com" in u for u in links))

    def test_crawl_sample_returns_empty_when_disabled(self) -> None:
        analyzer = SimpleHTMLAnalyzer()
        analyzer.feed("<html><body></body></html>")
        base = AuditContext(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            html="",
            headers={},
            robots_txt="",
            robots_error=None,
            sitemap_urls=[],
            analyzer=analyzer,
        )
        agent = SeoAuditAgent(fetch_func=_fetch_ok, robots_loader=_robots_loader)
        contexts = agent._crawl_sample(
            base,
            RobotsResult(content="", error=None, sitemap_urls=[]),
            depth=0,
            limit=10,
            include_sitemaps=False,
            max_seconds=0.0,
            robots_rules={"disallow": [], "allow": [], "crawl_delay": None},
        )
        self.assertEqual(contexts, [])

    def test_crawl_sample_honors_time_budget_and_sitemaps(self) -> None:
        analyzer = SimpleHTMLAnalyzer()
        analyzer.feed("<html><body><a href=\"/\">home</a></body></html>")
        base = AuditContext(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            html="",
            headers={},
            robots_txt="",
            robots_error=None,
            sitemap_urls=[],
            analyzer=analyzer,
        )
        agent = SeoAuditAgent(fetch_func=_fetch_ok, robots_loader=_robots_loader, crawl_delay=0.0)

        with patch("seo_agent.audit.load_sitemap_urls", return_value=["https://other.com/", "https://example.com"]):
            with patch("seo_agent.audit.time.monotonic", side_effect=[0.0, 999.0]):
                contexts = agent._crawl_sample(
                    base,
                    RobotsResult(content="", error=None, sitemap_urls=["https://example.com/sitemap.xml"]),
                    depth=1,
                    limit=10,
                    include_sitemaps=True,
                    max_seconds=1.0,
                    robots_rules={"disallow": [], "allow": [], "crawl_delay": None},
                )
        self.assertEqual(contexts, [])

    def test_crawl_sample_enqueues_deeper_links(self) -> None:
        pages: dict[str, str] = {
            "https://example.com/p2": "<html><body><a href=\"/p3\">p3</a></body></html>",
            "https://example.com/p3": "<html><body></body></html>",
        }

        def fetch(url: str, **_kwargs) -> FetchResult:
            html = pages.get(url, "<html><body></body></html>")
            return FetchResult(body=html, final_url=url, headers={}, status_code=200, error=None, duration_ms=1, content_size=len(html))

        analyzer = SimpleHTMLAnalyzer()
        analyzer.feed("<html><body><a href=\"/p2\">p2</a></body></html>")
        base = AuditContext(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            html="",
            headers={},
            robots_txt="",
            robots_error=None,
            sitemap_urls=[],
            analyzer=analyzer,
        )
        agent = SeoAuditAgent(fetch_func=fetch, robots_loader=_robots_loader, crawl_delay=0.0)
        contexts = agent._crawl_sample(
            base,
            RobotsResult(content="", error=None, sitemap_urls=[]),
            depth=2,
            limit=1,
            include_sitemaps=False,
            max_seconds=0.0,
            robots_rules={"disallow": [], "allow": [], "crawl_delay": None},
        )
        self.assertEqual(len(contexts), 1)

    def test_crawl_sample_skips_fetch_errors_and_parse_errors(self) -> None:
        def fetch(url: str, **_kwargs) -> FetchResult:
            if url.endswith("/badfetch"):
                return FetchResult(body="", final_url=url, headers={}, status_code=0, error="boom", duration_ms=1, content_size=0)
            return FetchResult(body="<html><body></body></html>", final_url=url, headers={}, status_code=200, error=None, duration_ms=1, content_size=10)

        analyzer = SimpleHTMLAnalyzer()
        analyzer.feed("<html><body><a href=\"/badfetch\">x</a></body></html>")
        base = AuditContext(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            html="",
            headers={},
            robots_txt="",
            robots_error=None,
            sitemap_urls=[],
            analyzer=analyzer,
        )

        class _BadAnalyzer(SimpleHTMLAnalyzer):
            def feed(self, data):  # type: ignore[override]
                raise ValueError("parse failed")

        agent = SeoAuditAgent(fetch_func=fetch, robots_loader=_robots_loader, crawl_delay=0.0)
        # First URL triggers fetch error branch.
        contexts = agent._crawl_sample(
            base,
            RobotsResult(content="", error=None, sitemap_urls=[]),
            depth=1,
            limit=2,
            include_sitemaps=False,
            max_seconds=0.0,
            robots_rules={"disallow": [], "allow": [], "crawl_delay": None},
        )
        self.assertEqual(contexts, [])

        # Second URL triggers parse error branch.
        analyzer2 = SimpleHTMLAnalyzer()
        analyzer2.feed("<html><body><a href=\"/badparse\">y</a></body></html>")
        base2 = AuditContext(
            url=base.url,
            final_url=base.final_url,
            status_code=base.status_code,
            html=base.html,
            headers=base.headers,
            robots_txt=base.robots_txt,
            robots_error=base.robots_error,
            sitemap_urls=base.sitemap_urls,
            analyzer=analyzer2,
        )
        with patch("seo_agent.audit.SimpleHTMLAnalyzer", _BadAnalyzer):
            contexts = agent._crawl_sample(
                base2,
                RobotsResult(content="", error=None, sitemap_urls=[]),
                depth=1,
                limit=2,
                include_sitemaps=False,
                max_seconds=0.0,
                robots_rules={"disallow": [], "allow": [], "crawl_delay": None},
            )
        self.assertEqual(contexts, [])

    def test_apply_page_metrics_updates_issue_evidence_and_impact(self) -> None:
        agent = SeoAuditAgent(fetch_func=_fetch_ok, robots_loader=_robots_loader)
        issues = [
            Issue(id="a", severity="important", category="general", title="A", what="", steps=[], outcome="", validation="", page="https://example.com/"),
            Issue(
                id="b",
                severity="important",
                category="general",
                title="B",
                what="",
                steps=[],
                outcome="",
                validation="",
                page="https://example.com/low",
                impact="low",  # type: ignore[arg-type]
            ),
            Issue(id="c", severity="important", category="general", title="C", what="", steps=[], outcome="", validation="", page=""),
        ]
        metrics = {
            "https://example.com/": {"impressions": 1000.0, "clicks": 10.0},
            "https://example.com/low": {"impressions": 100.0, "clicks": 1.0},
        }
        agent._apply_page_metrics(issues, metrics)
        self.assertIn("gsc", issues[0].evidence)
        self.assertEqual(issues[0].impact, "high")
        self.assertEqual(issues[1].impact, "medium")
