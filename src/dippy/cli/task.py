"""
Taskwarrior command handler for Dippy.

Approves exact, built-in read commands and requires confirmation for mutations.
"""

from __future__ import annotations

import re

from dippy.cli import Classification, HandlerContext

COMMANDS = ["task"]

_REPORT_ACTIONS = frozenset(
    {
        "active",
        "all",
        "blocked",
        "blocking",
        "completed",
        "list",
        "long",
        "ls",
        "minimal",
        "newest",
        "next",
        "oldest",
        "overdue",
        "ready",
        "recurring",
        "unblocked",
        "waiting",
    }
)

# Built-in reports and read-only commands from Taskwarrior 3.x.  These are kept
# explicit because reports and aliases can also be defined in taskrc.
SAFE_ACTIONS = _REPORT_ACTIONS | frozenset(
    {
        # Export, metadata, and fixed reports
        "export",
        "count",
        "ids",
        "uuids",
        "information",
        "projects",
        "stats",
        "tags",
        "timesheet",
        "burndown.annual",
        "burndown.daily",
        "burndown.weekly",
        "burndown.monthly",
        "ghistory.annual",
        "ghistory.daily",
        "ghistory.weekly",
        "ghistory.monthly",
        "history.annual",
        "history.daily",
        "history.weekly",
        "history.monthly",
        "summary",
        "calendar",
        "calc",
        "colors",
        "columns",
        "commands",
        "diagnostics",
        "help",
        "logo",
        "reports",
        "show",
        "udas",
        "version",
        # Machine-readable helpers used by completion and integrations
        "_aliases",
        "_columns",
        "_commands",
        "_config",
        "_context",
        "_get",
        "_ids",
        "_projects",
        "_show",
        "_tags",
        "_udas",
        "_unique",
        "_urgency",
        "_uuids",
        "_version",
        "_zshattributes",
        "_zshcommands",
        "_zshids",
        "_zshuuids",
    }
)

# Exact mutation commands, unsafe commands, and accepted built-in aliases.
UNSAFE_ACTIONS = frozenset(
    {
        "add",
        "annotate",
        "append",
        "prepend",
        "modify",
        "done",
        "start",
        "stop",
        "delete",
        "rm",
        "denotate",
        "duplicate",
        "edit",
        "log",
        "purge",
        "undo",
        "import",
        "import-v2",
        "synchronize",
        "sync",
        "execute",
        "news",
        # Both commands can mutate configuration or current context.  Their
        # apparently read-only forms remain ambiguous and therefore ask.
        "config",
        "context",
    }
)

_KNOWN_ACTIONS = SAFE_ACTIONS | UNSAFE_ACTIONS
_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_TAG_FILTER = re.compile(r"[+-][A-Za-z0-9_][A-Za-z0-9_.-]*")
_ATTRIBUTE_FILTER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*(?::|!?=|[<>]=?).*")
_FILTER_OPERATORS = frozenset({"(", ")", "and", "or", "xor"})
_SAFE_OVERRIDES = frozenset({"rc.json.array=on"})


def _has_expansion_risk(value: str) -> bool:
    """Detect syntax that may expand after Parable's lossy outer-quote removal."""
    if any(character in value for character in "*?["):
        return True
    if value.startswith("~"):
        return True

    for start, character in enumerate(value):
        if character != "{":
            continue
        for end in range(start + 1, len(value)):
            if value[end] != "}":
                continue
            has_comma = "," in value[start + 1 : end]
            has_sequence = any(
                value[index : index + 2] == ".." for index in range(start + 1, end - 1)
            )
            if has_comma or has_sequence:
                return True
            break
    return False


def _cook_literal_token(token: str) -> tuple[str, bool] | None:
    """Apply Bash quote removal to one non-expanded word.

    Parable intentionally preserves quote fragments and backslashes in token
    values. Taskwarrior sees the cooked argv instead. This handles Bash's
    ordinary single quotes, double quotes, and backslash rules; expansion-like
    or malformed syntax fails closed instead of approximating with shlex.
    """
    cooked: list[str] = []

    state = "unquoted"
    index = 0
    while index < len(token):
        character = token[index]
        if state == "single":
            if character == "'":
                state = "unquoted"
            else:
                cooked.append(character)
            index += 1
            continue

        if state == "double":
            if character == '"':
                state = "unquoted"
                index += 1
                continue
            if character == "\\":
                if index + 1 >= len(token):
                    return None
                following = token[index + 1]
                if following in {"$", "`", '"', "\\", "\n"}:
                    if following != "\n":
                        cooked.append(following)
                else:
                    cooked.extend(("\\", following))
                index += 2
                continue
            if character in {"$", "`"}:
                return None
            cooked.append(character)
            index += 1
            continue

        if character == "'":
            state = "single"
            index += 1
            continue
        if character == '"':
            state = "double"
            index += 1
            continue
        if character == "\\":
            if index + 1 >= len(token):
                return None
            following = token[index + 1]
            if following != "\n":
                cooked.append(following)
            index += 2
            continue
        if character in {"$", "`"}:
            return None
        cooked.append(character)
        index += 1

    if state != "unquoted":
        return None
    value = "".join(cooked)
    return value, _has_expansion_risk(value)


def _is_abbreviation(token: str) -> bool:
    """Whether token is a non-exact prefix of a built-in command."""
    return token not in _KNOWN_ACTIONS and any(
        action.startswith(token) for action in _KNOWN_ACTIONS
    )


def _is_filter(token: str) -> bool:
    """Recognize unambiguous filter forms allowed before the command."""
    return bool(
        _UUID.fullmatch(token)
        or _TAG_FILTER.fullmatch(token)
        or _ATTRIBUTE_FILTER.fullmatch(token)
        or token in _FILTER_OPERATORS
        or (len(token) >= 2 and token.startswith("/") and token.endswith("/"))
        or (token.startswith("(") and token.endswith(")") and ":" in token)
    )


def classify(ctx: HandlerContext) -> Classification:
    """Classify Taskwarrior using command-source semantics only.

    This static handler trusts the effective external environment and taskrc,
    including TASKRC, aliases, and hooks, like other Dippy handlers. It
    classifies literal command-source semantics only; command-line overrides
    that could alter behavior fail closed.
    """
    tokens = ctx.tokens
    base = tokens[0] if tokens else "task"
    if len(tokens) < 2:
        return Classification("ask", description=f"{base} (missing action)")
    if any(ctx.word_has_expansions):
        return Classification("ask", description=f"{base} (dynamic argument)")

    cooked_args = [_cook_literal_token(token) for token in tokens[1:]]
    if any(token is None for token in cooked_args):
        return Classification("ask", description=f"{base} (unsupported quoting)")
    if any(token[1] for token in cooked_args if token is not None):
        return Classification("ask", description=f"{base} (shell expansion risk)")
    args = [token[0] for token in cooked_args if token is not None]

    if args in (["--version"], ["--help"], ["-h"]):
        return Classification("allow", description=f"{base} {args[0]}")

    # Arbitrary taskrc overrides can define aliases, hooks, and default reports.
    # Only the harmless JSON array formatting override needed for machine reads
    # is accepted.
    unsafe_override = next(
        (
            token
            for token in args
            if token.startswith(("rc.", "rc:", "rc=")) and token not in _SAFE_OVERRIDES
        ),
        None,
    )
    if unsafe_override is not None:
        return Classification(
            "ask", description=f"{base} rc override ({unsafe_override})"
        )

    separators = [index for index, token in enumerate(args) if token == "--"]
    if len(separators) > 1:
        return Classification("ask", description=f"{base} (ambiguous -- separator)")

    unsafe = next((token for token in args if token in UNSAFE_ACTIONS), None)
    if unsafe is not None:
        return Classification("ask", description=f"{base} {unsafe} (write/unsafe)")

    # Taskwarrior accepts unique command abbreviations.  Their meaning changes
    # as commands are added, so only exact command names are trusted.
    abbreviation = next((token for token in args if _is_abbreviation(token)), None)
    if abbreviation is not None:
        return Classification(
            "ask", description=f"{base} {abbreviation} (abbreviated action)"
        )

    actions = [
        (index, token) for index, token in enumerate(args) if token in SAFE_ACTIONS
    ]
    if len(actions) > 1:
        export_with_report = (
            len(actions) == 2
            and actions[0][1] == "export"
            and actions[1][1] in _REPORT_ACTIONS
        )
        if not export_with_report:
            action_names = ", ".join(action for _, action in actions)
            return Classification(
                "ask", description=f"{base} (multiple actions: {action_names})"
            )
        actions = actions[:1]
    if not actions:
        unknown = next(
            (
                token
                for token in args
                if token != "--"
                and token not in _SAFE_OVERRIDES
                and not _is_filter(token)
            ),
            None,
        )
        description = (
            f"{base} {unknown} (unknown action)"
            if unknown is not None
            else f"{base} (missing action)"
        )
        return Classification("ask", description=description)

    action_index, action = actions[0]

    # `--` prevents alias expansion only for tokens after it.  It is useful when
    # placed before the action, but cannot protect an action that came first.
    if separators and separators[0] > action_index:
        return Classification("ask", description=f"{base} (ambiguous -- separator)")

    # Before the command, Taskwarrior may encounter a configured alias or custom
    # report first.  Fail closed on bare words while allowing ordinary filters,
    # literal UUIDs, and the one approved formatting override.
    unknown_prefix = next(
        (
            token
            for token in args[:action_index]
            if token != "--" and token not in _SAFE_OVERRIDES and not _is_filter(token)
        ),
        None,
    )
    if unknown_prefix is not None:
        return Classification(
            "ask", description=f"{base} {unknown_prefix} (unknown action)"
        )

    return Classification("allow", description=f"{base} {action}")


# Taskwarrior treats suffix help flags as action arguments, so its handler must
# classify those complete commands instead of using the analyzer's generic
# suffix-help shortcut.
setattr(classify, "_dippy_handles_help", True)
