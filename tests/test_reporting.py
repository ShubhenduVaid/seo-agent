import json
import unittest

from seo_agent.analyzer import SimpleHTMLAnalyzer
from seo_agent.models import AuditContext, Issue
from seo_agent.reporting import render_report


def _context(final_url: str = "https://example.com/") -> AuditContext:
    analyzer = SimpleHTMLAnalyzer()
    analyzer.feed("<html><head><title>T</title></head><body><h1>H</h1></body></html>")
    return AuditContext(
        url=final_url,
        final_url=final_url,
        status_code=200,
        html="",
        headers={},
        robots_txt=None,
        robots_error=None,
        sitemap_urls=[],
        analyzer=analyzer,
        fetch_duration_ms=123,
        content_size=2048,
    )


def _issue(
    issue_id: str,
    severity: str,
    title: str,
    category: str = "general",
    impact: str = "medium",
    effort: str = "medium",
    confidence: str = "medium",
    page: str = "https://example.com/",
) -> Issue:
    return Issue(
        id=issue_id,
        severity=severity,
        category=category,
        title=title,
        what="what",
        steps=["step1", "step2"],
        outcome="outcome",
        validation="validation",
        page=page,
        impact=impact,  # type: ignore[arg-type]
        effort=effort,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        evidence={"k": "v"},
    )


class ReportingTests(unittest.TestCase):
    def test_render_report_text_with_no_issues_renders_empty_groups(self) -> None:
        output = render_report(_context(), "goal", [], fmt="text")
        self.assertIn("Next actions (recommended order):", output)
        self.assertIn("- None detected.", output)
        self.assertIn("- None detected for this category.", output)

    def test_render_report_text_renders_quick_wins_and_crawl_summary(self) -> None:
        ctx = _context()
        issues = [
            _issue("security.hsts_missing", "important", "HSTS header missing", category="security", impact="high", effort="low"),
            _issue("crawl.sitemap", "recommended", "Sitemap missing", category="crawl", impact="low", effort="high"),
        ]
        crawl_summary = {
            "pages_crawled": 2,
            "duplicate_titles": [{"value": "Same", "pages": ["https://example.com/a", "https://example.com/b"]}],
            "duplicate_h1": [{"value": "A" * 80, "pages": ["https://example.com/a", "https://example.com/b"]}],
            "duplicate_descriptions": [],
        }
        output = render_report(ctx, "traffic growth", issues, fmt="text", crawl_summary=crawl_summary)
        self.assertIn("Quick wins:", output)
        self.assertIn("HSTS header missing", output)
        self.assertIn("Crawl summary", output)
        self.assertIn("Duplicate title", output)
        self.assertIn("Duplicate H1", output)

    def test_render_report_markdown_includes_sections(self) -> None:
        ctx = _context()
        issues = [
            _issue("status.5xx", "critical", "Server error", category="status", impact="high", effort="low"),
            _issue("content.meta", "important", "Meta description missing", category="content", impact="high", effort="low"),
        ]
        crawl_summary = {"pages_crawled": 1, "duplicate_titles": [], "duplicate_h1": [], "duplicate_descriptions": []}
        md = render_report(ctx, "migration security trust", issues, fmt="markdown", crawl_summary=crawl_summary)
        self.assertIn("# SEO Audit Report", md)
        self.assertIn("## Next actions (recommended order)", md)
        self.assertIn("## Quick wins", md)
        self.assertIn("## Crawl summary", md)
        self.assertIn("## 1. Critical Issues", md)
        self.assertIn("## 2. Important Optimizations", md)
        self.assertIn("## 3. Recommended Enhancements", md)

    def test_render_report_json_includes_priority_scores(self) -> None:
        ctx = _context()
        issues = [
            _issue("links.internal", "important", "Low internal linking", category="links", impact="high", effort="low"),
            _issue("performance.slow", "important", "Slow response", category="performance", impact="high", effort="high"),
        ]
        data = json.loads(render_report(ctx, "traffic growth", issues, fmt="json"))
        self.assertIn("top_actions", data)
        self.assertIn("quick_wins", data)
        self.assertTrue(all("priority_score" in item for item in data["top_actions"]))

    def test_render_report_sarif_contains_results_and_rules(self) -> None:
        ctx = _context()
        issues = [
            _issue("content.title_missing", "critical", "Title tag missing", category="content", impact="high", effort="low"),
            _issue("crawl.sitemap_not_advertised", "recommended", "XML sitemap not advertised", category="crawl"),
        ]
        data = json.loads(render_report(ctx, "goal", issues, fmt="sarif"))
        self.assertEqual(data.get("version"), "2.1.0")
        run = data.get("runs", [{}])[0]
        tool = run.get("tool", {}).get("driver", {})
        self.assertEqual(tool.get("name"), "SEO Audit Agent")
        results = run.get("results", [])
        self.assertEqual(len(results), 2)
        levels = {result.get("level") for result in results}
        self.assertIn("error", levels)
        self.assertIn("note", levels)
        rule_ids = {rule.get("id") for rule in tool.get("rules", [])}
        self.assertIn("content.title_missing", rule_ids)
