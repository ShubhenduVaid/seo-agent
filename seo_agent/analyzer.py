from __future__ import annotations

from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple


class SimpleHTMLAnalyzer(HTMLParser):
    """Lightweight HTML collector that keeps only what the audit needs."""

    def __init__(self) -> None:
        super().__init__()
        self.title_parts: List[str] = []
        self.in_title = False
        self.html_attrs: Dict[str, Optional[str]] = {}
        self.current_heading_tag: Optional[str] = None
        self.current_heading_parts: List[str] = []
        self.headings: List[Tuple[str, str]] = []
        self.meta_tags: List[Dict[str, Optional[str]]] = []
        self.link_tags: List[Dict[str, Optional[str]]] = []
        self.links: List[str] = []
        self.scripts: List[Dict[str, Optional[str]]] = []
        self.images: List[Dict[str, Optional[str]]] = []
        self.ld_json_blocks: List[str] = []
        self.in_ld_json = False
        self.ld_json_parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {k.lower(): v for k, v in attrs}
        if tag == "html" and not self.html_attrs:
            self.html_attrs = attrs_dict
        elif tag == "title":
            self.in_title = True
            self.title_parts = []
        elif tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.current_heading_tag = tag
            self.current_heading_parts = []
        elif tag == "meta":
            self.meta_tags.append(attrs_dict)
        elif tag == "link":
            self.link_tags.append(attrs_dict)
        elif tag == "a":
            href = attrs_dict.get("href")
            if href:
                self.links.append(href)
        elif tag == "script":
            self.scripts.append(attrs_dict)
            script_type = (attrs_dict.get("type") or "").lower()
            if script_type == "application/ld+json":
                self.in_ld_json = True
                self.ld_json_parts = []
        elif tag == "img":
            self.images.append(attrs_dict)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        elif tag == self.current_heading_tag and self.current_heading_tag:
            text = "".join(self.current_heading_parts).strip()
            if text:
                self.headings.append((self.current_heading_tag, text))
            self.current_heading_tag = None
            self.current_heading_parts = []
        elif tag == "script" and self.in_ld_json:
            block = "".join(self.ld_json_parts).strip()
            if block:
                self.ld_json_blocks.append(block)
            self.in_ld_json = False
            self.ld_json_parts = []

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.current_heading_tag:
            self.current_heading_parts.append(data)
        if self.in_ld_json:
            self.ld_json_parts.append(data)

    @property
    def title(self) -> str:
        return "".join(self.title_parts).strip()
