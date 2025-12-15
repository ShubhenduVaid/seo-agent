from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, TypedDict


class RobotsRules(TypedDict):
    disallow: List[str]
    allow: List[str]
    crawl_delay: Optional[float]


@dataclass
class _RobotsGroup:
    user_agents: List[str]
    disallow: List[str]
    allow: List[str]
    crawl_delay: Optional[float] = None


def parse_robots(robots_content: Optional[str], user_agent: str) -> RobotsRules:
    """Parse robots.txt and return the rules applicable to `user_agent`.

    This is a conservative, stdlib-only parser:
    - supports multiple groups and user-agent precedence (longest match wins)
    - supports Allow/Disallow and Crawl-delay
    - ignores directives outside a user-agent group
    """
    if not robots_content:
        return {"disallow": [], "allow": [], "crawl_delay": None}

    groups: List[_RobotsGroup] = []
    current: Optional[_RobotsGroup] = None
    seen_directive = False

    for raw_line in robots_content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        field, value = line.split(":", 1)
        field_lower = field.strip().lower()
        value_stripped = value.strip()

        if field_lower == "user-agent":
            ua_value = value_stripped.lower()
            if current is None or seen_directive:
                current = _RobotsGroup(user_agents=[], disallow=[], allow=[], crawl_delay=None)
                groups.append(current)
                seen_directive = False
            current.user_agents.append(ua_value)
            continue

        if current is None:
            continue
        seen_directive = True

        if field_lower == "disallow":
            if value_stripped == "":
                continue
            current.disallow.append(value_stripped)
        elif field_lower == "allow":
            if value_stripped == "":
                continue
            current.allow.append(value_stripped)
        elif field_lower == "crawl-delay":
            try:
                current.crawl_delay = float(value_stripped)
            except ValueError:
                continue

    selected = _select_group(groups, user_agent)
    if not selected:
        return {"disallow": [], "allow": [], "crawl_delay": None}
    return {"disallow": selected.disallow, "allow": selected.allow, "crawl_delay": selected.crawl_delay}


def is_allowed(url: str, rules: RobotsRules) -> bool:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    allow_match = _best_match_length(rules.get("allow", []), path)
    disallow_match = _best_match_length(rules.get("disallow", []), path)
    if allow_match >= disallow_match:
        return True
    return False


def _select_group(groups: List[_RobotsGroup], user_agent: str) -> Optional[_RobotsGroup]:
    ua = (user_agent or "").lower()
    best: Optional[_RobotsGroup] = None
    best_len = -1
    for group in groups:
        for agent_token in group.user_agents:
            if not agent_token:
                continue
            if agent_token == "*":
                match_len = 1
            elif agent_token in ua:
                match_len = len(agent_token)
            else:
                continue
            if match_len > best_len:
                best = group
                best_len = match_len
    return best


def _best_match_length(patterns: List[str], path: str) -> int:
    best = 0
    for pattern in patterns:
        if not pattern:
            continue
        if _pattern_matches(pattern, path):
            best = max(best, len(pattern.rstrip("$")))
    return best


def _pattern_matches(pattern: str, path: str) -> bool:
    end_anchor = pattern.endswith("$")
    raw = pattern[:-1] if end_anchor else pattern
    # Robots patterns are anchored at the start; support `*` wildcard.
    regex = re.escape(raw).replace(r"\*", ".*")
    if end_anchor:
        regex = f"^{regex}$"
    else:
        regex = f"^{regex}"
    try:
        return re.match(regex, path) is not None
    except re.error:  # pragma: no cover - defensive
        # Fall back to simple prefix semantics for malformed patterns.
        return path.startswith(raw)

