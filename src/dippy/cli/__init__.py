"""
CLI-specific command handlers for Dippy.

Each handler module exports:
- COMMANDS: list[str] - command names this handler supports
- classify(ctx: HandlerContext) -> Classification - classify command for approval

External packages can register handlers through the ``dippy.handlers`` entry
point group. See the project documentation for details.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, replace
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional, Protocol, Sequence

if TYPE_CHECKING:
    from dippy.core.config import Config


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HandlerContext:
    """Context passed to handlers."""

    tokens: list[str]
    config: Config | None = None
    word_has_expansions: tuple[bool, ...] = ()
    """Per-token flag: True if the original word contained bash expansions ($VAR, $(cmd), etc.)."""


@dataclass(frozen=True)
class Classification:
    """Result of classifying a command.

    Handlers return this to indicate:
    - allow: command is safe, no further checking needed
    - ask: command needs user confirmation
    - delegate: check inner_command to determine safety
    """

    action: Literal["allow", "ask", "delegate"]
    inner_command: str | None = None  # Required when action="delegate"
    description: str | None = None  # Optional, overrides default description
    redirect_targets: tuple[
        str, ...
    ] = ()  # File targets to check against redirect rules
    remote: bool = False  # Inner command runs in remote context (container, ssh, etc.)


class CLIHandler(Protocol):
    """Protocol for CLI handler modules."""

    COMMANDS: Sequence[str]

    def classify(self, ctx: HandlerContext) -> Classification:
        """Classify command for approval.

        Args:
            ctx: Handler context containing command tokens

        Returns Classification with action and optional description.
        """
        ...


@dataclass(frozen=True)
class _ExternalCLIHandler:
    """Fail-safe runtime boundary around an external handler."""

    handler: CLIHandler
    entry_point_name: str
    entry_point_value: str

    @property
    def COMMANDS(self) -> Sequence[str]:
        return self.handler.COMMANDS

    def classify(self, ctx: HandlerContext) -> Classification:
        """Run an external classifier and convert plugin failures to ask."""
        try:
            result = self.handler.classify(ctx)
        except Exception:
            logger.warning(
                "External handler %s (%s) failed while classifying; defaulting to ask",
                self.entry_point_name,
                self.entry_point_value,
                exc_info=True,
            )
            return self._failure(ctx.tokens)

        if not self._is_valid_classification(result):
            logger.warning(
                "External handler %s (%s) returned an invalid Classification; "
                "defaulting to ask",
                self.entry_point_name,
                self.entry_point_value,
            )
            return self._failure(ctx.tokens)

        if result.description is not None:
            return result

        try:
            get_description = getattr(self.handler, "get_description", None)
        except Exception:
            logger.warning(
                "External handler %s (%s) failed while resolving get_description; "
                "defaulting to ask",
                self.entry_point_name,
                self.entry_point_value,
                exc_info=True,
            )
            return self._failure(ctx.tokens)
        if get_description is None:
            return replace(result, description=self._default_description(ctx.tokens))
        if not callable(get_description):
            logger.warning(
                "External handler %s (%s) has a non-callable get_description; "
                "defaulting to ask",
                self.entry_point_name,
                self.entry_point_value,
            )
            return self._failure(ctx.tokens)

        try:
            description = get_description(ctx.tokens)
        except Exception:
            logger.warning(
                "External handler %s (%s) failed while describing a command; "
                "defaulting to ask",
                self.entry_point_name,
                self.entry_point_value,
                exc_info=True,
            )
            return self._failure(ctx.tokens)

        if not isinstance(description, str) or not description:
            logger.warning(
                "External handler %s (%s) returned an invalid description; "
                "defaulting to ask",
                self.entry_point_name,
                self.entry_point_value,
            )
            return self._failure(ctx.tokens)
        return replace(result, description=description)

    def get_description(self, tokens: list[str]) -> str:
        """Return the description already made safe by ``classify``."""
        return self._default_description(tokens)

    def _failure(self, tokens: list[str]) -> Classification:
        return Classification("ask", description=self._default_description(tokens))

    @staticmethod
    def _default_description(tokens: list[str]) -> str:
        return " ".join(tokens[:2]) if tokens else "external handler"

    @staticmethod
    def _is_valid_classification(result: object) -> bool:
        return (
            isinstance(result, Classification)
            and result.action in ("allow", "ask", "delegate")
            and (result.inner_command is None or isinstance(result.inner_command, str))
            and (result.description is None or isinstance(result.description, str))
            and isinstance(result.redirect_targets, tuple)
            and all(isinstance(target, str) for target in result.redirect_targets)
            and isinstance(result.remote, bool)
        )


# How many tokens to include in description (base + action + ...)
# Default is 2 (e.g., "git status", "docker ps")
DESCRIPTION_DEPTH = {
    "aws": 3,  # aws s3 ls
    "gcloud": 3,  # gcloud compute instances
    "gsutil": 2,  # gsutil ls
    "az": 3,  # az vm list
}


def get_description(tokens: list[str], handler_name: str = None) -> str:
    """Compute description from tokens based on handler type."""
    if not tokens:
        return "unknown"

    # Check if handler has its own get_description function
    base = tokens[0]
    handler = get_handler(handler_name or base)
    if handler and hasattr(handler, "get_description"):
        return handler.get_description(tokens)

    depth = DESCRIPTION_DEPTH.get(handler_name or base, 2)
    return " ".join(tokens[:depth])


def _discover_handlers() -> dict[str, CLIHandler]:
    """Discover built-in and external handlers by command name.

    External handlers are added after built-ins so plugins cannot replace
    Dippy's security-critical built-in classifications.
    """
    handlers: dict[str, CLIHandler] = {}
    cli_dir = Path(__file__).parent
    for file in cli_dir.glob("*.py"):
        if file.name.startswith("_"):
            continue
        module_name = file.stem
        try:
            module = importlib.import_module(f".{module_name}", package="dippy.cli")
            for cmd in getattr(module, "COMMANDS", []):
                handlers[cmd] = module
        except ImportError:
            continue

    _discover_entry_point_handlers(handlers)
    return handlers


def _discover_entry_point_handlers(handlers: dict[str, CLIHandler]) -> None:
    """Add valid ``dippy.handlers`` entry points to *handlers*.

    An entry point may resolve to a module or another object. The resolved
    object must expose ``COMMANDS`` as a non-empty list or tuple of non-empty
    strings and a callable ``classify`` attribute. Each entry point is loaded
    exactly once. Invalid or broken plugins are ignored.
    """
    try:
        try:
            discovered = entry_points(group="dippy.handlers")
        except TypeError:
            # Python 3.8 does not support selecting a group with an argument.
            discovered = entry_points().get("dippy.handlers", [])  # type: ignore[union-attr]
    except Exception:
        logger.debug("Failed to discover dippy.handlers entry points", exc_info=True)
        return

    for entry_point in discovered:
        try:
            external_handler = entry_point.load()
            commands = getattr(external_handler, "COMMANDS", None)
            classify = getattr(external_handler, "classify", None)
            if (
                not isinstance(commands, (list, tuple))
                or not commands
                or not all(isinstance(command, str) and command for command in commands)
                or not callable(classify)
            ):
                logger.debug(
                    "Entry point %s (%s) does not satisfy the handler contract; skipping",
                    entry_point.name,
                    entry_point.value,
                )
                continue
        except Exception:
            logger.debug(
                "Failed to load handler entry point %s",
                entry_point.name,
                exc_info=True,
            )
            continue

        handler = _ExternalCLIHandler(
            handler=external_handler,
            entry_point_name=entry_point.name,
            entry_point_value=entry_point.value,
        )

        for command in commands:
            if command in handlers:
                logger.debug(
                    "Handler entry point %s cannot replace existing command %s; skipping",
                    entry_point.name,
                    command,
                )
                continue
            handlers[command] = handler


# Build handler mapping at import time
KNOWN_HANDLERS = _discover_handlers()


def get_handler(command_name: str) -> Optional[CLIHandler]:
    """
    Get the handler module for a CLI command.

    Returns None if no handler exists for the command.
    """
    return KNOWN_HANDLERS.get(command_name)
