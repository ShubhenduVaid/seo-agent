from __future__ import annotations

import configparser
from typing import Any, Dict, List, Tuple


class ConfigError(Exception):
    pass


_BOOL_KEYS = {
    "insecure",
    "quiet",
    "fail_on_critical",
    "crawl_sitemaps",
    "check_links",
    "enable_plugins",
}
_INT_KEYS = {
    "timeout",
    "crawl_depth",
    "crawl_limit",
    "link_check_limit_per_page",
}
_FLOAT_KEYS = {
    "crawl_delay",
    "crawl_max_seconds",
}
_STR_KEYS = {
    "url",
    "goal",
    "user_agent",
    "format",
    "report",
    "save_baseline",
    "compare",
    "psi_json",
    "gsc_pages_csv",
}
_LIST_KEYS = {
    "crawl_include",
    "crawl_exclude",
}

_VALID_FORMATS = {"text", "json", "markdown", "sarif"}


def load_config(path: str) -> Tuple[Dict[str, Any], List[str]]:
    parser = configparser.ConfigParser()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except OSError as exc:
        raise ConfigError(f"Could not read config file {path}: {exc}") from exc
    except configparser.Error as exc:
        raise ConfigError(f"Config file {path} is invalid: {exc}") from exc

    section = None
    for name in ("seo-agent", "seo_agent", "seoagent"):
        if name in parser:
            section = parser[name]
            break
    if section is None:
        return {}, []

    values: Dict[str, Any] = {}
    unknown: List[str] = []
    for raw_key, raw_value in section.items():
        key = raw_key.strip().lower().replace("-", "_")
        if key in _BOOL_KEYS:
            try:
                values[key] = section.getboolean(raw_key)
            except ValueError as exc:
                raise ConfigError(f"Invalid boolean for {raw_key}: {raw_value}") from exc
        elif key in _INT_KEYS:
            try:
                values[key] = int(raw_value)
            except ValueError as exc:
                raise ConfigError(f"Invalid integer for {raw_key}: {raw_value}") from exc
        elif key in _FLOAT_KEYS:
            try:
                values[key] = float(raw_value)
            except ValueError as exc:
                raise ConfigError(f"Invalid number for {raw_key}: {raw_value}") from exc
        elif key in _STR_KEYS:
            values[key] = raw_value.strip()
        elif key in _LIST_KEYS:
            values[key] = _split_list(raw_value)
        else:
            unknown.append(raw_key)

    if "format" in values:
        fmt = str(values["format"]).strip().lower()
        if fmt == "md":
            fmt = "markdown"
        if fmt not in _VALID_FORMATS:
            raise ConfigError(f"Unsupported format in config: {values['format']}")
        values["format"] = fmt

    return values, unknown


def _split_list(value: str) -> List[str]:
    items: List[str] = []
    for line in value.splitlines():
        for part in line.split(","):
            item = part.strip()
            if item:
                items.append(item)
    return items
