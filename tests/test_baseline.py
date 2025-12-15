import os
import tempfile
import unittest

from seo_agent.baseline import (
    _get_issues,
    _index_issues,
    build_baseline,
    diff_baselines,
    load_baseline,
    render_diff_markdown,
    render_diff_text,
    save_baseline,
)
from seo_agent.models import Issue


class BaselineTests(unittest.TestCase):
    def test_build_baseline_sorts_issues_by_page_then_id(self) -> None:
        issues = [
            Issue(
                id="b.issue",
                severity="important",
                category="general",
                title="B",
                what="",
                steps=[],
                outcome="",
                validation="",
                page="https://example.com/b",
            ),
            Issue(
                id="a.issue",
                severity="important",
                category="general",
                title="A",
                what="",
                steps=[],
                outcome="",
                validation="",
                page="https://example.com/a",
            ),
        ]
        baseline = build_baseline("https://example.com", "goal", issues)
        items = baseline.get("issues") or []
        self.assertEqual(items[0]["page"], "https://example.com/a")
        self.assertEqual(items[1]["page"], "https://example.com/b")

    def test_save_and_load_baseline_roundtrip(self) -> None:
        baseline = {"schema_version": 1, "url": "https://example.com", "goal": "g", "issues": [{"id": "x", "page": ""}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            save_baseline(path, baseline)
            loaded = load_baseline(path)
        self.assertEqual(loaded, baseline)

    def test_diff_baselines_counts_fixed_new_and_persisting(self) -> None:
        baseline = {"issues": [{"id": "a", "page": "p1", "severity": "critical"}]}
        current = {"issues": [{"id": "a", "page": "p1", "severity": "critical"}, {"id": "b", "page": "p2", "severity": "important"}]}
        diff = diff_baselines(baseline, current)
        summary = diff.get("summary") or {}
        self.assertEqual(summary.get("fixed"), 0)
        self.assertEqual(summary.get("new"), 1)
        self.assertEqual(summary.get("persisting"), 1)

    def test_diff_baselines_handles_non_list_issues(self) -> None:
        diff = diff_baselines({"issues": "nope"}, {"issues": None})
        summary = diff.get("summary") or {}
        self.assertEqual(summary.get("fixed"), 0)
        self.assertEqual(summary.get("new"), 0)
        self.assertEqual(summary.get("persisting"), 0)

    def test_render_diff_text_and_markdown_include_counts(self) -> None:
        diff = {
            "summary": {
                "fixed": 1,
                "new": 2,
                "persisting": 3,
                "fixed_by_severity": {"critical": 1, "important": 0},
                "new_by_severity": {"critical": 0, "important": 2},
            }
        }
        text = render_diff_text(diff)
        md = render_diff_markdown(diff)
        self.assertIn("Comparison vs baseline", text)
        self.assertIn("- Fixed: 1", text)
        self.assertIn("## Comparison vs baseline", md)
        self.assertIn("**New:** 2", md)

    def test_internal_helpers_skip_missing_ids(self) -> None:
        items = [{"id": "", "page": "p"}, {"id": "a", "page": "p"}]
        indexed = _index_issues(items)
        self.assertEqual(list(indexed.keys()), [("a", "p")])

    def test_get_issues_returns_empty_for_non_list(self) -> None:
        self.assertEqual(_get_issues({"issues": None}), [])
        self.assertEqual(_get_issues({"issues": {}}), [])
        self.assertEqual(_get_issues({"issues": []}), [])
