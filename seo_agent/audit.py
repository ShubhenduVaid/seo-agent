from __future__ import annotations

import time
import urllib.parse
from collections import deque
from typing import Callable, Dict, List

from .analyzer import SimpleHTMLAnalyzer
from .checks.html import get_meta
from .checks.registry import build_checks
from .checks.types import CheckEnv, CheckSpec
from .constants import DEFAULT_TIMEOUT, USER_AGENT
from .models import AuditContext, FetchResult, HeadResult, Issue, RobotsResult
from .network import fetch_url, head_request, load_robots_and_sitemaps, load_sitemap_urls, normalize_url
from .robots import RobotsRules, is_allowed, parse_robots
from .reporting import OutputFormat, render_report, render_unreachable


class SeoAuditAgent:
    def __init__(
        self,
        verify_ssl: bool = True,
        user_agent: str = USER_AGENT,
        timeout: int = DEFAULT_TIMEOUT,
        output_format: OutputFormat = "text",
        fetch_func: Callable[..., FetchResult] = fetch_url,
        head_func: Callable[..., HeadResult] = head_request,
        robots_loader: Callable[..., RobotsResult] = load_robots_and_sitemaps,
        crawl_delay: float = 0.3,
        check_links: bool = False,
        link_check_limit_per_page: int = 3,
        enable_plugins: bool = False,
        checks: List[CheckSpec] | None = None,
    ) -> None:
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.timeout = timeout
        self.output_format = output_format
        self._fetch = fetch_func
        self._head = head_func
        self._robots_loader = robots_loader
        self.crawl_delay = max(0.0, crawl_delay)
        self.check_links = bool(check_links)
        self.link_check_limit_per_page = max(0, int(link_check_limit_per_page))
        self._checks = checks if checks is not None else build_checks(enable_plugins=enable_plugins)

    def audit(self, url: str, goal: str) -> str:
        report, _issues = self.audit_with_details(url, goal)
        return report

    def audit_with_details(
        self,
        url: str,
        goal: str,
        crawl_depth: int = 0,
        crawl_limit: int = 0,
        include_sitemaps: bool = False,
        crawl_max_seconds: float = 0.0,
        page_metrics: Dict[str, Dict[str, float]] | None = None,
    ) -> tuple[str, List[Issue]]:
        try:
            normalized_url = normalize_url(url)
        except ValueError as exc:
            return render_unreachable(url, goal, str(exc)), []

        fetch_result = self._fetch(
            normalized_url,
            verify_ssl=self.verify_ssl,
            timeout=self.timeout,
            user_agent=self.user_agent,
        )
        if fetch_result.error:
            return render_unreachable(normalized_url, goal, fetch_result.error), []

        analyzer = SimpleHTMLAnalyzer()
        try:
            analyzer.feed(fetch_result.body)
        except Exception as exc:  # pragma: no cover - defensive
            return render_unreachable(normalized_url, goal, f"HTML parsing failed: {exc}"), []

        robots_result = self._robots_loader(
            fetch_result.final_url,
            verify_ssl=self.verify_ssl,
            timeout=self.timeout,
            user_agent=self.user_agent,
        )
        robots_rules = parse_robots(robots_result.content, self.user_agent)
        context = AuditContext(
            url=normalized_url,
            final_url=fetch_result.final_url,
            status_code=fetch_result.status_code,
            html=fetch_result.body,
            headers=fetch_result.headers,
            robots_txt=robots_result.content,
            robots_error=robots_result.error,
            sitemap_urls=robots_result.sitemap_urls,
            analyzer=analyzer,
            fetch_duration_ms=fetch_result.duration_ms,
            content_size=fetch_result.content_size,
            content_type=fetch_result.content_type,
            truncated=fetch_result.truncated,
        )

        issues = self._collect_issues(context, include_crawl_checks=True)

        effective_depth = max(crawl_depth, 1) if include_sitemaps else crawl_depth
        crawl_contexts: List[AuditContext] = []
        if crawl_limit and (effective_depth > 0 or include_sitemaps):
            crawl_contexts = self._crawl_sample(
                context,
                robots_result,
                depth=effective_depth,
                limit=crawl_limit,
                include_sitemaps=include_sitemaps,
                max_seconds=crawl_max_seconds,
                robots_rules=robots_rules,
            )
            for crawl_ctx in crawl_contexts:
                issues.extend(self._collect_issues(crawl_ctx, include_crawl_checks=False))

        crawl_summary = self._summarize_crawl(crawl_contexts) if crawl_contexts else None
        if page_metrics:
            self._apply_page_metrics(issues, page_metrics)
        return render_report(context, goal, issues, fmt=self.output_format, crawl_summary=crawl_summary), issues

    def _collect_issues(self, context: AuditContext, include_crawl_checks: bool = True) -> List[Issue]:
        env = CheckEnv(
            verify_ssl=self.verify_ssl,
            user_agent=self.user_agent,
            timeout=self.timeout,
            head=self._head,
            check_links=self.check_links,
            link_check_limit_per_page=self.link_check_limit_per_page,
        )
        issues: List[Issue] = []
        for check in self._checks:
            if not include_crawl_checks and not check.include_on_crawled_pages:
                continue
            issues.extend(check.func(context, env))
        for issue in issues:
            issue.page = context.final_url
        return issues

    def _crawl_sample(
        self,
        base_context: AuditContext,
        robots_result: RobotsResult,
        depth: int,
        limit: int,
        include_sitemaps: bool,
        max_seconds: float,
        robots_rules: RobotsRules,
    ) -> List[AuditContext]:
        if depth <= 0 or limit <= 0:
            return []
        domain = urllib.parse.urlparse(base_context.final_url).netloc.lower()
        seeds = self._collect_same_host_links(base_context.final_url, base_context.analyzer.links, domain)
        if include_sitemaps and robots_result.sitemap_urls:
            sitemap_urls = load_sitemap_urls(
                robots_result.sitemap_urls,
                verify_ssl=self.verify_ssl,
                timeout=self.timeout,
                user_agent=self.user_agent,
            )
            for u in sitemap_urls:
                parsed = urllib.parse.urlparse(u)
                if parsed.netloc.lower() != domain:
                    continue
                path = parsed.path or "/"
                seeds.append(normalize_url(urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))))

        queue = deque((url, 1) for url in seeds)
        base_parsed = urllib.parse.urlparse(base_context.final_url)
        base_path = base_parsed.path or "/"
        seen = {normalize_url(urllib.parse.urlunparse((base_parsed.scheme, base_parsed.netloc, base_path, "", "", "")))}
        contexts: List[AuditContext] = []
        crawl_delay_val = robots_rules.get("crawl_delay")
        min_delay = max(self.crawl_delay, crawl_delay_val if crawl_delay_val is not None else 0.0)
        start = time.monotonic()

        while queue and len(contexts) < limit:
            if max_seconds and (time.monotonic() - start) >= max_seconds:
                break
            url, current_depth = queue.popleft()
            if url in seen or current_depth > depth:
                continue
            seen.add(url)

            if not is_allowed(url, robots_rules):
                continue

            fetch_result = self._fetch(url, verify_ssl=self.verify_ssl, timeout=self.timeout, user_agent=self.user_agent)
            if fetch_result.error:
                continue

            analyzer = SimpleHTMLAnalyzer()
            try:
                analyzer.feed(fetch_result.body)
            except Exception:
                continue

            ctx = AuditContext(
                url=normalize_url(url),
                final_url=fetch_result.final_url,
                status_code=fetch_result.status_code,
                html=fetch_result.body,
                headers=fetch_result.headers,
                robots_txt=robots_result.content,
                robots_error=robots_result.error,
                sitemap_urls=robots_result.sitemap_urls,
                analyzer=analyzer,
                fetch_duration_ms=fetch_result.duration_ms,
                content_size=fetch_result.content_size,
                content_type=fetch_result.content_type,
                truncated=fetch_result.truncated,
            )
            contexts.append(ctx)

            if current_depth < depth:
                new_links = self._collect_same_host_links(fetch_result.final_url, analyzer.links, domain)
                for link in new_links:
                    if link not in seen:
                        queue.append((link, current_depth + 1))

            if min_delay > 0 and queue:
                time.sleep(min_delay)
        return contexts

    def _collect_same_host_links(self, base_url: str, hrefs: List[str], domain: str) -> List[str]:
        collected: List[str] = []
        for href in hrefs:
            resolved = urllib.parse.urljoin(base_url, href)
            parsed = urllib.parse.urlparse(resolved)
            if parsed.scheme not in {"http", "https"}:
                continue
            if parsed.netloc.lower() != domain:
                continue
            path = parsed.path or "/"
            normalized = normalize_url(urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", "")))
            if normalized not in collected:
                collected.append(normalized)
        return collected

    def _summarize_crawl(self, contexts: List[AuditContext]) -> Dict[str, object]:
        duplicate_titles: List[Dict[str, object]] = []
        duplicate_h1: List[Dict[str, object]] = []
        duplicate_descriptions: List[Dict[str, object]] = []

        titles_map: Dict[str, List[str]] = {}
        h1_map: Dict[str, List[str]] = {}
        desc_map: Dict[str, List[str]] = {}
        for ctx in contexts:
            title = ctx.analyzer.title
            if title:
                titles_map.setdefault(title, []).append(ctx.final_url)
            h1_text = next((text for tag, text in ctx.analyzer.headings if tag == "h1"), "")
            if h1_text:
                h1_map.setdefault(h1_text, []).append(ctx.final_url)
            meta_desc = get_meta(ctx.analyzer, "description")
            desc = (meta_desc.get("content") or "").strip() if meta_desc else ""
            if desc:
                desc_map.setdefault(desc, []).append(ctx.final_url)

        for value, pages in titles_map.items():
            if len(pages) > 1:
                duplicate_titles.append({"value": value, "pages": pages[:5]})
        for value, pages in h1_map.items():
            if len(pages) > 1:
                duplicate_h1.append({"value": value, "pages": pages[:5]})
        for value, pages in desc_map.items():
            if len(pages) > 1:
                duplicate_descriptions.append({"value": value, "pages": pages[:5]})

        return {
            "pages_crawled": len(contexts),
            "duplicate_titles": duplicate_titles,
            "duplicate_h1": duplicate_h1,
            "duplicate_descriptions": duplicate_descriptions,
        }

    def _apply_page_metrics(self, issues: List[Issue], page_metrics: Dict[str, Dict[str, float]]) -> None:
        for issue in issues:
            page = issue.page or ""
            if not page:
                continue
            parsed = urllib.parse.urlparse(page)
            path = parsed.path or "/"
            key = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
            metrics = page_metrics.get(key)
            if not metrics:
                continue
            issue.evidence.setdefault("gsc", {}).update(metrics)
            impressions = float(metrics.get("impressions", 0.0) or 0.0)
            if impressions >= 1000:
                issue.impact = "high"
            elif impressions >= 100 and issue.impact == "low":
                issue.impact = "medium"
