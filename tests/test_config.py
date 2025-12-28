import os
import tempfile
import unittest

from seo_agent.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def _write_config(self, content: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
        try:
            handle.write(content)
            handle.flush()
        finally:
            handle.close()
        return handle.name

    def _cleanup(self, path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def test_load_config_parses_types_and_unknown(self) -> None:
        path = self._write_config(
            """
            [seo-agent]
            goal = traffic growth
            format = JSON
            crawl-depth = 2
            crawl_delay = 0.5
            quiet = true
            unknown_key = value
            """
        )
        try:
            values, unknown = load_config(path)
        finally:
            self._cleanup(path)
        self.assertEqual(values.get("goal"), "traffic growth")
        self.assertEqual(values.get("format"), "json")
        self.assertEqual(values.get("crawl_depth"), 2)
        self.assertEqual(values.get("crawl_delay"), 0.5)
        self.assertTrue(values.get("quiet"))
        self.assertIn("unknown_key", unknown)

    def test_load_config_invalid_format_raises(self) -> None:
        path = self._write_config(
            """
            [seo-agent]
            format = xml
            """
        )
        try:
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            self._cleanup(path)

    def test_load_config_missing_section_returns_empty(self) -> None:
        path = self._write_config(
            """
            [other]
            goal = traffic growth
            """
        )
        try:
            values, unknown = load_config(path)
        finally:
            self._cleanup(path)
        self.assertEqual(values, {})
        self.assertEqual(unknown, [])


if __name__ == "__main__":
    unittest.main()
