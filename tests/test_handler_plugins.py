"""Tests for external handler plugin discovery via entry points."""

from __future__ import annotations

import logging
import types
from importlib.metadata import EntryPoint
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dippy.cli import (
    Classification,
    HandlerContext,
    _discover_entry_point_handlers,
    _discover_handlers,
    get_handler,
)
from dippy.core.config import Config, Rule
from dippy.dippy import check_command


def _handler(commands: list[str], action: str = "allow") -> types.ModuleType:
    module = types.ModuleType(f"test_handler_{commands[0]}")
    module.COMMANDS = commands

    def classify(ctx: HandlerContext) -> Classification:
        return Classification(action, description=" ".join(ctx.tokens))

    module.classify = classify
    return module


def _entry_point(value: str, handler: object) -> MagicMock:
    entry_point = MagicMock()
    entry_point.name = value.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
    entry_point.value = value
    entry_point.load.return_value = handler
    return entry_point


def _permission(result: dict) -> str:
    return result["hookSpecificOutput"]["permissionDecision"]


def _check_with_plugins(
    command: str,
    entry_points: list[EntryPoint],
    modules: dict[str, types.ModuleType],
    config: Config | None = None,
) -> dict:
    with patch.dict("sys.modules", modules), patch(
        "dippy.cli.entry_points", return_value=entry_points
    ):
        handlers = _discover_handlers()

    with patch.dict("dippy.cli.KNOWN_HANDLERS", handlers, clear=True):
        return check_command(command, config or Config(), Path.cwd())


class TestEntryPointDiscovery:
    def test_discovers_module_only_handler_once(self):
        handler = _handler(["snooctl", "snoo"])
        entry_point = _entry_point("reddit_dippy.snooctl", handler)
        handlers: dict[str, object] = {}

        with patch("dippy.cli.entry_points", return_value=[entry_point]):
            _discover_entry_point_handlers(handlers)

        assert handlers["snooctl"].handler is handler
        assert handlers["snoo"].handler is handler
        entry_point.load.assert_called_once_with()

    def test_discovers_module_object_handler_once(self):
        handler = _handler(["custom"])
        entry_point = _entry_point("plugin.handlers:CUSTOM_HANDLER", handler)
        handlers: dict[str, object] = {}

        with patch("dippy.cli.entry_points", return_value=[entry_point]):
            _discover_entry_point_handlers(handlers)

        assert handlers["custom"].handler is handler
        entry_point.load.assert_called_once_with()

    def test_existing_handler_takes_precedence(self):
        builtin = _handler(["kubectl"])
        plugin = _handler(["kubectl", "plugin-only"])
        entry_point = _entry_point("plugin.handlers", plugin)
        handlers = {"kubectl": builtin}

        with patch("dippy.cli.entry_points", return_value=[entry_point]):
            _discover_entry_point_handlers(handlers)

        assert handlers["kubectl"] is builtin
        assert handlers["plugin-only"].handler is plugin

    def test_broken_plugin_does_not_block_other_plugins(self):
        broken = _entry_point("broken.handler", object())
        broken.load.side_effect = RuntimeError("broken import")
        working_handler = _handler(["working"])
        working = _entry_point("working.handler", working_handler)
        handlers: dict[str, object] = {}

        with patch("dippy.cli.entry_points", return_value=[broken, working]):
            _discover_entry_point_handlers(handlers)

        assert handlers["working"].handler is working_handler

    def test_invalid_handler_contract_is_skipped(self):
        invalid_handlers = [
            types.SimpleNamespace(COMMANDS=[], classify=lambda ctx: None),
            types.SimpleNamespace(COMMANDS=[""], classify=lambda ctx: None),
            types.SimpleNamespace(COMMANDS=["valid", 42], classify=lambda ctx: None),
            types.SimpleNamespace(COMMANDS="bad", classify=lambda ctx: None),
            types.SimpleNamespace(COMMANDS=["missing-classify"]),
            types.SimpleNamespace(COMMANDS=["not-callable"], classify=None),
        ]

        for invalid_handler in invalid_handlers:
            handlers: dict[str, object] = {}
            with patch(
                "dippy.cli.entry_points",
                return_value=[_entry_point("invalid.handler", invalid_handler)],
            ):
                _discover_entry_point_handlers(handlers)

            assert handlers == {}

    def test_discovery_failure_leaves_builtins_unchanged(self):
        builtin = _handler(["git"])
        handlers = {"git": builtin}

        with patch(
            "dippy.cli.entry_points", side_effect=RuntimeError("metadata error")
        ):
            _discover_entry_point_handlers(handlers)

        assert handlers == {"git": builtin}

    def test_python_38_entry_point_api(self):
        handler = _handler(["legacy"])
        entry_point = _entry_point("legacy.handler", handler)

        def legacy_entry_points(**kwargs):
            if kwargs:
                raise TypeError("group is unsupported")
            return {"dippy.handlers": [entry_point]}

        handlers: dict[str, object] = {}
        with patch("dippy.cli.entry_points", side_effect=legacy_entry_points):
            _discover_entry_point_handlers(handlers)

        assert handlers["legacy"].handler is handler


class TestHandlerLookup:
    def test_builtins_are_discovered_as_handler_modules(self):
        handlers = _discover_handlers()

        assert handlers["kubectl"].__name__ == "dippy.cli.kubectl"
        assert handlers["git"].__name__ == "dippy.cli.git"

    def test_get_handler_returns_discovered_plugin_without_reloading(self):
        handler = _handler(["external"], action="ask")
        entry_point = _entry_point("external.handler", handler)
        handlers: dict[str, object] = {}

        with patch("dippy.cli.entry_points", return_value=[entry_point]):
            _discover_entry_point_handlers(handlers)

        with patch.dict("dippy.cli.KNOWN_HANDLERS", handlers):
            discovered = get_handler("external")

        assert discovered.handler is handler
        result = discovered.classify(
            HandlerContext(
                tokens=["external", "status"],
                config=None,
                word_has_expansions=(False, False),
            )
        )
        assert result == Classification("ask", description="external status")
        entry_point.load.assert_called_once_with()

    def test_get_handler_returns_none_for_unknown_command(self):
        assert get_handler("definitely-not-a-command") is None


class TestAnalyzerIntegration:
    @pytest.mark.parametrize(
        ("entry_point_value", "use_object"),
        [
            ("test_module_plugin", False),
            ("test_object_plugin:HANDLER", True),
        ],
    )
    def test_real_entry_point_forms_reach_check_command(
        self, entry_point_value, use_object
    ):
        handler = _handler(["plugin"])
        modules = {}
        if use_object:
            container = types.ModuleType("test_object_plugin")
            container.HANDLER = handler
            modules[container.__name__] = container
        else:
            handler.__name__ = "test_module_plugin"
            modules[handler.__name__] = handler
        entry_point = EntryPoint(
            name="plugin", value=entry_point_value, group="dippy.handlers"
        )

        result = _check_with_plugins("plugin status", [entry_point], modules)

        assert _permission(result) == "allow"

    def test_config_deny_takes_precedence_over_plugin(self):
        handler = _handler(["plugin"])
        handler.classify = MagicMock(return_value=Classification("allow"))
        handler.__name__ = "test_config_plugin"
        entry_point = EntryPoint(
            name="plugin", value=handler.__name__, group="dippy.handlers"
        )
        config = Config(rules=[Rule("deny", "plugin *", message="blocked")])

        result = _check_with_plugins(
            "plugin status", [entry_point], {handler.__name__: handler}, config
        )

        assert _permission(result) == "deny"
        handler.classify.assert_not_called()

    @pytest.mark.parametrize(
        ("config", "expected"),
        [
            (Config(), "ask"),
            (
                Config(
                    redirect_rules=[
                        Rule("deny", "secrets.txt", message="protected output")
                    ]
                ),
                "deny",
            ),
        ],
    )
    def test_plugin_redirect_targets_remain_subject_to_redirect_security(
        self, config, expected
    ):
        handler = _handler(["plugin"])
        handler.classify = lambda ctx: Classification(
            "allow", description="plugin export", redirect_targets=("secrets.txt",)
        )
        handler.__name__ = "test_redirect_plugin"
        entry_point = EntryPoint(
            name="plugin", value=handler.__name__, group="dippy.handlers"
        )

        result = _check_with_plugins(
            "plugin export", [entry_point], {handler.__name__: handler}, config
        )

        assert _permission(result) == expected

    @pytest.mark.parametrize(
        "classify",
        [
            pytest.param(MagicMock(side_effect=RuntimeError("boom")), id="exception"),
            pytest.param(MagicMock(return_value=None), id="non-classification"),
            pytest.param(
                MagicMock(return_value=Classification("invalid")),
                id="invalid-action",
            ),
            pytest.param(
                MagicMock(
                    return_value=Classification("allow", redirect_targets=["bad"])
                ),
                id="malformed-fields",
            ),
        ],
    )
    def test_plugin_classification_failures_default_to_ask(self, classify, caplog):
        handler = _handler(["plugin"])
        handler.classify = classify
        handler.__name__ = "test_broken_classify_plugin"
        entry_point = EntryPoint(
            name="plugin", value=handler.__name__, group="dippy.handlers"
        )

        with caplog.at_level(logging.WARNING, logger="dippy.cli"):
            result = _check_with_plugins(
                "plugin mutate", [entry_point], {handler.__name__: handler}
            )

        assert _permission(result) == "ask"
        assert "defaulting to ask" in caplog.text

    @pytest.mark.parametrize(
        "get_description",
        [
            pytest.param(MagicMock(side_effect=RuntimeError("boom")), id="exception"),
            pytest.param(MagicMock(return_value=None), id="non-string"),
            pytest.param(MagicMock(return_value=""), id="empty"),
            pytest.param(42, id="non-callable"),
        ],
    )
    def test_plugin_description_failures_default_to_ask(self, get_description, caplog):
        handler = _handler(["plugin"])
        handler.classify = lambda ctx: Classification("allow")
        handler.get_description = get_description
        handler.__name__ = "test_broken_description_plugin"
        entry_point = EntryPoint(
            name="plugin", value=handler.__name__, group="dippy.handlers"
        )

        with caplog.at_level(logging.WARNING, logger="dippy.cli"):
            result = _check_with_plugins(
                "plugin inspect", [entry_point], {handler.__name__: handler}
            )

        assert _permission(result) == "ask"
        assert "defaulting to ask" in caplog.text

    def test_plugin_cannot_replace_builtin_handler(self):
        handler = _handler(["git"])
        handler.classify = MagicMock(return_value=Classification("allow"))
        handler.__name__ = "test_collision_plugin"
        entry_point = EntryPoint(
            name="git", value=handler.__name__, group="dippy.handlers"
        )

        result = _check_with_plugins(
            "git push", [entry_point], {handler.__name__: handler}
        )

        assert _permission(result) == "ask"
        handler.classify.assert_not_called()

    def test_first_discovered_plugin_wins_duplicate_command(self):
        first = _handler(["plugin"], action="ask")
        first.__name__ = "test_first_plugin"
        second = _handler(["plugin"], action="allow")
        second.classify = MagicMock(return_value=Classification("allow"))
        second.__name__ = "test_second_plugin"
        entry_points = [
            EntryPoint(name="first", value=first.__name__, group="dippy.handlers"),
            EntryPoint(name="second", value=second.__name__, group="dippy.handlers"),
        ]

        result = _check_with_plugins(
            "plugin status",
            entry_points,
            {first.__name__: first, second.__name__: second},
        )

        assert _permission(result) == "ask"
        second.classify.assert_not_called()
