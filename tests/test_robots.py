import unittest

from seo_agent.robots import is_allowed, parse_robots


class RobotsTests(unittest.TestCase):
    def test_parse_robots_is_conservative_and_handles_edge_cases(self) -> None:
        robots = """
        Disallow: /outside-group

        User-agent
        User-agent:
        Allow:
        Disallow:
        Crawl-delay: not-a-number

        User-agent: googlebot
        Disallow: /private

        User-agent: mybot
        Disallow: /private
        Allow: /private/public$
        Crawl-delay: 1.5
        """
        rules = parse_robots(robots, user_agent="MyBot/1.0")
        self.assertEqual(rules.get("crawl_delay"), 1.5)
        self.assertIn("/private", rules.get("disallow", []))
        self.assertIn("/private/public$", rules.get("allow", []))

        # Anchor patterns apply to the path (without query).
        self.assertTrue(is_allowed("https://example.com/private/public", rules))
        self.assertFalse(is_allowed("https://example.com/private", rules))

        # Query paths are included in matching when present.
        query_rules = {"allow": ["/private/public?x=1"], "disallow": ["/private"], "crawl_delay": None}
        self.assertTrue(is_allowed("https://example.com/private/public?x=1", query_rules))
        self.assertFalse(is_allowed("https://example.com/private/other?x=1", query_rules))

    def test_parse_robots_returns_empty_when_no_group_matches(self) -> None:
        robots = "User-agent: googlebot\nDisallow: /"
        rules = parse_robots(robots, user_agent="Bingbot")
        self.assertEqual(rules.get("disallow"), [])
        self.assertEqual(rules.get("allow"), [])

    def test_is_allowed_prefers_longest_match_and_skips_empty_patterns(self) -> None:
        rules = {"allow": ["", "/tmp*"], "disallow": ["/tmp/private"], "crawl_delay": None}
        self.assertTrue(is_allowed("https://example.com/tmp/file", rules))
        self.assertFalse(is_allowed("https://example.com/tmp/private", rules))
