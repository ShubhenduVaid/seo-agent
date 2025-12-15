import unittest
from unittest.mock import patch

from seo_agent.checks.registry import DEFAULT_CHECKS, build_checks
from seo_agent.checks.types import CheckSpec


def _noop_check(_context, _env):
    return []


class _FakeEntryPoint:
    def __init__(self, obj, raises: bool = False) -> None:
        self._obj = obj
        self._raises = raises

    def load(self):
        if self._raises:
            raise RuntimeError("load failed")
        return self._obj


class _FakeEntryPoints:
    def __init__(self, group) -> None:
        self._group = group

    def select(self, group: str):
        if group != "seo_agent.checks":
            return []
        return self._group


class RegistryTests(unittest.TestCase):
    def test_build_checks_defaults(self) -> None:
        checks = build_checks(enable_plugins=False)
        self.assertEqual(len(checks), len(DEFAULT_CHECKS))

    def test_build_checks_loads_plugins_from_select(self) -> None:
        plugin_spec = CheckSpec(_noop_check)
        plugin_callable = _noop_check
        eps = _FakeEntryPoints(
            [
                _FakeEntryPoint(plugin_spec),
                _FakeEntryPoint(plugin_callable),
                _FakeEntryPoint(object()),  # ignored (not callable, not CheckSpec)
                _FakeEntryPoint(plugin_callable, raises=True),  # ignored (load error)
            ]
        )

        with patch("importlib.metadata.entry_points", return_value=eps):
            checks = build_checks(enable_plugins=True)

        self.assertGreaterEqual(len(checks), len(DEFAULT_CHECKS) + 2)
        self.assertTrue(any(isinstance(c, CheckSpec) and c.func is plugin_callable for c in checks))

    def test_build_checks_loads_plugins_from_dict_style_entry_points(self) -> None:
        plugin_callable = _noop_check
        eps = {"seo_agent.checks": [_FakeEntryPoint(plugin_callable)]}
        with patch("importlib.metadata.entry_points", return_value=eps):
            checks = build_checks(enable_plugins=True)
        self.assertTrue(any(isinstance(c, CheckSpec) and c.func is plugin_callable for c in checks))

