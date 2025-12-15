import unittest
from email.message import Message
from typing import Dict, Optional
from unittest.mock import patch

from seo_agent.network import (
    _extract_urls_from_sitemap,
    fetch_url,
    head_request,
    load_robots_and_sitemaps,
    load_sitemap_urls,
    normalize_url,
)


class _FakeResponse:
    def __init__(self, final_url: str, body: bytes, headers: Optional[Dict[str, str]] = None, status: int = 200) -> None:
        self._final_url = final_url
        self._body = body
        self.status = status
        msg = Message()
        for k, v in (headers or {}).items():
            msg[k] = v
        self.headers = msg

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            return self._body
        return self._body[:n]

    def geturl(self) -> str:
        return self._final_url

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class NetworkTests(unittest.TestCase):
    def test_normalize_url_rejects_unsupported_scheme(self) -> None:
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")

    def test_fetch_url_rejects_non_html_content(self) -> None:
        resp = _FakeResponse(
            "https://example.com/",
            b"{}",
            headers={"Content-Type": "application/json; charset=utf-8"},
            status=200,
        )
        with patch("seo_agent.network.urllib.request.urlopen", return_value=resp):
            result = fetch_url("https://example.com/")
        self.assertIn("Unsupported content type", result.error or "")
        self.assertEqual(result.body, "")
        self.assertEqual(result.content_size, 0)

    def test_fetch_url_truncates_html_and_sets_flag(self) -> None:
        resp = _FakeResponse(
            "https://example.com/",
            b"a" * 11,
            headers={"Content-Type": "text/html; charset=utf-8"},
            status=200,
        )
        with patch("seo_agent.network.MAX_HTML_BYTES", 10):
            with patch("seo_agent.network.urllib.request.urlopen", return_value=resp):
                result = fetch_url("https://example.com/")
        self.assertTrue(result.truncated)
        self.assertEqual(result.content_size, 10)
        self.assertEqual(len(result.body), 10)

    def test_fetch_url_uses_unverified_ssl_context_when_disabled(self) -> None:
        captured: dict[str, object] = {}

        def fake_urlopen(req, timeout: int, context=None):
            captured["context"] = context
            return _FakeResponse(
                "https://example.com/",
                b"<html></html>",
                headers={"Content-Type": "text/html; charset=utf-8"},
                status=200,
            )

        with patch("seo_agent.network.ssl._create_unverified_context", return_value=object()):
            with patch("seo_agent.network.urllib.request.urlopen", side_effect=fake_urlopen):
                result = fetch_url("https://example.com/", verify_ssl=False)
        self.assertIsNone(result.error)
        self.assertIsNotNone(captured.get("context"))

    def test_fetch_url_handles_urlopen_error(self) -> None:
        with patch("seo_agent.network.urllib.request.urlopen", side_effect=RuntimeError("boom")):
            result = fetch_url("https://example.com/")
        self.assertIn("boom", result.error or "")
        self.assertEqual(result.status_code, 0)

    def test_load_robots_and_sitemaps_extracts_sitemap_urls(self) -> None:
        body = "User-agent: *\nDisallow:\nSitemap: https://example.com/sitemap.xml\n"
        resp = _FakeResponse(
            "https://example.com/robots.txt",
            body.encode("utf-8"),
            headers={"Content-Type": "text/plain; charset=utf-8"},
            status=200,
        )
        with patch("seo_agent.network.urllib.request.urlopen", return_value=resp):
            robots = load_robots_and_sitemaps("https://example.com/page")
        self.assertIn("Sitemap:", robots.content or "")
        self.assertEqual(robots.error, None)
        self.assertEqual(robots.sitemap_urls, ["https://example.com/sitemap.xml"])

    def test_load_robots_and_sitemaps_handles_error(self) -> None:
        with patch("seo_agent.network.urllib.request.urlopen", side_effect=OSError("nope")):
            robots = load_robots_and_sitemaps("https://example.com/page")
        self.assertIsNotNone(robots.error)
        self.assertEqual(robots.sitemap_urls, [])

    def test_load_sitemap_urls_parses_xml_and_text_and_skips_failures(self) -> None:
        xml = "<urlset><url><loc>https://example.com/a</loc></url></urlset>"
        txt = "https://example.com/b\nhttps://example.com/c\nnot-a-url\n"
        responses = [
            RuntimeError("temporary"),
            _FakeResponse(
                "https://example.com/sitemap.xml",
                xml.encode("utf-8"),
                headers={"Content-Type": "application/xml; charset=utf-8"},
                status=200,
            ),
            _FakeResponse(
                "https://example.com/sitemap.txt",
                txt.encode("utf-8"),
                headers={"Content-Type": "text/plain; charset=utf-8"},
                status=200,
            ),
        ]
        with patch("seo_agent.network.urllib.request.urlopen", side_effect=responses):
            urls = load_sitemap_urls(
                ["https://example.com/fail.xml", "https://example.com/sitemap.xml", "https://example.com/sitemap.txt"],
                max_sitemaps=3,
            )
        self.assertIn("https://example.com/a", urls)
        self.assertIn("https://example.com/b", urls)
        self.assertIn("https://example.com/c", urls)

    def test_extract_urls_from_sitemap_handles_empty_and_invalid_xml(self) -> None:
        self.assertEqual(_extract_urls_from_sitemap(""), [])
        body = "https://example.com/x\nhttps://example.com/y\n"
        self.assertEqual(_extract_urls_from_sitemap(body), ["https://example.com/x", "https://example.com/y"])

    def test_head_request_returns_headers_and_status(self) -> None:
        def fake_urlopen(req, timeout: int, context=None):
            self.assertEqual(req.get_method(), "HEAD")
            return _FakeResponse(
                "https://example.com/asset.js",
                b"",
                headers={"Cache-Control": "max-age=3600"},
                status=200,
            )

        with patch("seo_agent.network.urllib.request.urlopen", side_effect=fake_urlopen):
            result = head_request("https://example.com/asset.js")
        self.assertEqual(result.error, None)
        self.assertEqual(result.status_code, 200)
        self.assertIn("Cache-Control", result.headers)

    def test_head_request_handles_error(self) -> None:
        with patch("seo_agent.network.urllib.request.urlopen", side_effect=RuntimeError("nope")):
            result = head_request("https://example.com/asset.js")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.status_code, 0)
