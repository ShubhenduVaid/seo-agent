from __future__ import annotations

from typing import Dict, List, Optional

from seo_agent.analyzer import SimpleHTMLAnalyzer


def get_meta(analyzer: SimpleHTMLAnalyzer, name: str) -> Optional[Dict[str, str]]:
    name_lower = name.lower()
    for meta in analyzer.meta_tags:
        meta_name = meta.get("name")
        if meta_name and meta_name.lower() == name_lower:
            return {k: v or "" for k, v in meta.items()}
    return None


def get_meta_property_or_name(analyzer: SimpleHTMLAnalyzer, value: str) -> Optional[Dict[str, str]]:
    value_lower = value.lower()
    for meta in analyzer.meta_tags:
        meta_name = meta.get("name")
        meta_prop = meta.get("property")
        if (meta_name and meta_name.lower() == value_lower) or (meta_prop and meta_prop.lower() == value_lower):
            return {k: v or "" for k, v in meta.items()}
    return None


def get_canonical(analyzer: SimpleHTMLAnalyzer) -> Optional[str]:
    for link in analyzer.link_tags:
        rel = (link.get("rel") or "").lower()
        if "canonical" in rel and link.get("href"):
            return link.get("href")
    return None


def get_canonicals(analyzer: SimpleHTMLAnalyzer) -> List[str]:
    canonicals: List[str] = []
    for link in analyzer.link_tags:
        rel = (link.get("rel") or "").lower()
        href = link.get("href")
        if "canonical" in rel and href:
            canonicals.append(href)
    return canonicals


def extract_schema_types(data: object) -> List[str]:
    types: List[str] = []
    if isinstance(data, dict):
        direct_type = data.get("@type")
        if isinstance(direct_type, str):
            types.append(direct_type)
        elif isinstance(direct_type, list):
            types.extend([str(t) for t in direct_type if t])
        graph = data.get("@graph")
        if isinstance(graph, list):
            for node in graph:
                types.extend(extract_schema_types(node))
    elif isinstance(data, list):
        for item in data:
            types.extend(extract_schema_types(item))
    return types
