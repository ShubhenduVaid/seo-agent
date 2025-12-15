from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List

from seo_agent.models import AuditContext, HeadResult, Issue

HeadFunc = Callable[..., HeadResult]


@dataclass(frozen=True)
class CheckEnv:
    verify_ssl: bool
    user_agent: str
    timeout: int
    head: HeadFunc
    check_links: bool = False
    link_check_limit_per_page: int = 3


CheckFunc = Callable[[AuditContext, CheckEnv], List[Issue]]


@dataclass(frozen=True)
class CheckSpec:
    func: CheckFunc
    include_on_crawled_pages: bool = True
