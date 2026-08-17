"""Test cases for the Taskwarrior CLI handler."""

from __future__ import annotations

import pytest

from conftest import is_approved, needs_confirmation
from dippy.cli import get_handler
from dippy.cli.task import _cook_literal_token


UNSAFE_ACTIONS = [
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
    "config",
    "context",
]


def get_reason(result: dict) -> str:
    """Extract the human-readable classification reason."""
    output = result.get("hookSpecificOutput", {})
    return output.get("permissionDecisionReason", "").lstrip("🐤 ").strip()


@pytest.mark.parametrize(
    "command",
    [
        "task rc.json.array=on modified.after:2026-07-18 status:completed description.contains:approval export",
        "task status:pending export",
        "task export status:pending",
        "task 123e4567-e89b-42d3-a456-426614174000 export",
        "task +journal status:completed export",
        "task project:Home or -work count",
        "task '(project:Home or project:Garden)' list",
        "task /meeting/ count",
        "task description.contains:'approval needed' export",
        "task export rc.json.array=on",
        "task export custom-report",
        "task rc.json.array=on export custom-report",
        "task -- export custom-report",
        "task -- export",
        "task status:pending -- export",
        "task --version",
        "task --help",
        "task -h",
    ],
)
def test_common_reads_are_approved(check, command: str) -> None:
    assert is_approved(check(command)), f"Expected approved for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        "task description.contains:done export",
        "task project:export status.not:deleted count",
        "task export description.contains:modify",
        "task status:completed information",
    ],
)
def test_filters_that_contain_command_names_are_approved(check, command: str) -> None:
    assert is_approved(check(command)), f"Expected approved for: {command}"


@pytest.mark.parametrize(
    "action",
    [
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
        "timesheet",
        "unblocked",
        "waiting",
        "export",
        "count",
        "ids",
        "uuids",
        "information",
        "projects",
        "stats",
        "tags",
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
    ],
)
def test_exact_builtin_reads_are_approved(check, action: str) -> None:
    assert is_approved(check(f"task {action}")), f"Expected approved for: {action}"


@pytest.mark.parametrize(
    "action",
    UNSAFE_ACTIONS,
)
def test_writes_and_unsafe_commands_need_confirmation(check, action: str) -> None:
    command = f"task 123e4567-e89b-42d3-a456-426614174000 {action} value"
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "action",
    UNSAFE_ACTIONS,
)
def test_unsafe_action_cannot_be_hidden_after_a_read(check, action: str) -> None:
    command = f"task export {action}"
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        "task",
        "task status:pending",
        "task 123e4567-e89b-42d3-a456-426614174000",
        "task inbox",
        "task history",
        "task ghistory",
        "task burndown",
        "task exp",
        "task info",
        "task status:pending ex",
        "task custom-report export",
        "task export count",
        "task export done",
        "task done export",
        "task export --",
        "task -- -- export",
        "task status:pending -- -- export",
    ],
)
def test_unknown_ambiguous_and_abbreviated_commands_need_confirmation(
    check, command: str
) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        "task rc.json.array=off status:pending export",
        "task rc.report.next.command=delete export",
        "task rc.alias.export=delete export",
        "task rc:/tmp/taskrc export",
        "task rc=/tmp/alternate.taskrc export",
        "task export rc=/tmp/alternate.taskrc",
        "task rc=/tmp/alternate.taskrc -- export",
        "task -- rc=/tmp/alternate.taskrc export",
        "task rc=/tmp/alternate.taskrc export --help",
        "task rc=/tmp/alternate.taskrc export --version",
    ],
)
def test_arbitrary_rc_overrides_need_confirmation(check, command: str) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "override",
    [
        "r''c=/tmp/alternate.taskrc",
        'r""c=/tmp/alternate.taskrc',
        r"r\c=/tmp/alternate.taskrc",
        "r''c:/tmp/alternate.taskrc",
        'r""c.alias.export=delete',
        r"r\c.hooks=on",
    ],
)
@pytest.mark.parametrize(
    "template",
    [
        "task {override} export",
        "task export {override}",
        "task {override} -- export",
        "task -- {override} export",
        "task export {override} --help",
        "task export {override} --version",
    ],
)
def test_fragmented_rc_overrides_need_confirmation(
    check, override: str, template: str
) -> None:
    command = template.format(override=override)
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        "task a''dd unsafe",
        'task export m""odify +unsafe',
        r"task ex\ecute --help",
        "task n''ews --version",
        r"task \-\- add unsafe",
        r"task export -\-",
        "task status:pending '-''-' '-''-' export",
    ],
)
def test_fragmented_unsafe_actions_and_separators_need_confirmation(
    check, command: str
) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        "task export r{c,x}=evil.taskrc",
        "task r{c,x}=evil.taskrc export",
        "task export r{c..x}=evil.taskrc",
        "task export r?=evil.taskrc",
        "task export r*=evil.taskrc",
        "task export r[cx]=evil.taskrc",
        "task export 'r'{c,x}'=evil.taskrc'",
        'task export "r"{c,x}"=evil.taskrc"',
        "task export 'r'?='evil.taskrc'",
        'task export "r"*="evil.taskrc"',
    ],
)
def test_shell_expansion_cannot_synthesize_task_overrides(check, command: str) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        "task description.contains:'?' export",
        r"task description.contains:\? export",
        "task description.contains:'{approval,review}' export",
        r"task description.contains:\{approval,review\} export",
        "task export r'{'c,x'}'=literal",
        r"task export r\{c,x\}=literal",
        "task export 'custom*'",
        "task export 'custom{one,two}'",
        r"task export custom\?",
    ],
)
def test_quoted_and_escaped_expansion_syntax_conservatively_asks(
    check, command: str
) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "source,expected",
    [
        ("r''c=/tmp/taskrc", ("rc=/tmp/taskrc", False)),
        ('r""c:/tmp/taskrc', ("rc:/tmp/taskrc", False)),
        (r"r\c.alias.export=delete", ("rc.alias.export=delete", False)),
        (
            "description.contains:'approval needed'",
            ("description.contains:approval needed", False),
        ),
        (r'key:"a\\qb"', (r"key:a\qb", False)),
        (r"\-\-", ("--", False)),
        ("r{c,x}=taskrc", ("r{c,x}=taskrc", True)),
        (r"r\{c,x\}=literal", ("r{c,x}=literal", True)),
        ("description.contains:'?'", ("description.contains:?", True)),
    ],
)
def test_literal_token_cooking(source: str, expected: tuple[str, bool]) -> None:
    assert _cook_literal_token(source) == expected


@pytest.mark.parametrize(
    "source", ["'unterminated", '"unterminated', "trailing\\", "$'rc='"]
)
def test_unsupported_literal_token_cooking_fails_closed(source: str) -> None:
    assert _cook_literal_token(source) is None


@pytest.mark.parametrize(
    "command",
    [
        "task $COMMAND",
        "task ${COMMAND}",
        "task status:$STATUS export",
        "task $FILTER export",
        "task $(echo export)",
        "task `echo export`",
    ],
)
def test_runtime_expansions_need_confirmation(check, command: str) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        'task "$COMMAND"',
        "task ${COMMAND:-export}",
        'task status:"$STATUS" export',
        "task $COMMAND --help",
        "task ${COMMAND:-export} -h",
        "task -- $COMMAND --help",
    ],
)
def test_quoted_defaulted_and_help_suffixed_expansions_fail_closed(
    check, command: str
) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "action",
    UNSAFE_ACTIONS,
)
@pytest.mark.parametrize("help_flag", ["--help", "-h", "--version"])
def test_unsafe_commands_with_help_flags_need_confirmation(
    check, action: str, help_flag: str
) -> None:
    command = f"task {action} {help_flag}"
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command",
    [
        "task -- add unsafe",
        "task status:pending -- modify +unsafe",
        "task -- execute command",
        "task -- add --help",
    ],
)
def test_separator_cannot_hide_unsafe_actions(check, command: str) -> None:
    assert needs_confirmation(check(command)), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command,expected",
    [
        ("task export next", True),
        ("task status:pending export next", True),
        ("task export next all", False),
        ("task next export", False),
        ("task export count", False),
        ("task export $REPORT", False),
        ("task export next modify +unsafe", False),
    ],
)
def test_export_report_selector(check, command: str, expected: bool) -> None:
    result = check(command)
    if expected:
        assert is_approved(result), f"Expected approved for: {command}"
    else:
        assert needs_confirmation(result), f"Expected confirmation for: {command}"


@pytest.mark.parametrize(
    "command,expected_text",
    [
        ("task rc.alias.export=delete export", "rc override"),
        ("task exp", "abbreviated action"),
        ("task custom-report export", "unknown action"),
        ("task export --", "separator"),
        ("task $COMMAND", "dynamic argument"),
        ("task add unsafe", "write/unsafe"),
        ("task export count", "multiple actions"),
    ],
)
def test_ask_descriptions_explain_taskwarrior_risk(
    check, command: str, expected_text: str
) -> None:
    reason = get_reason(check(command))
    assert expected_text in reason, f"Expected {expected_text!r} in {reason!r}"


def test_handler_metadata_controls_generic_behavior(check) -> None:
    task_handler = get_handler("task")
    git_handler = get_handler("git")

    assert task_handler is not None
    assert getattr(task_handler.classify, "_dippy_handles_help", False)
    assert git_handler is not None
    assert not getattr(git_handler.classify, "_dippy_handles_help", False)
    assert needs_confirmation(check("task add --help"))
    assert is_approved(check("git status --help"))


@pytest.mark.parametrize(
    "command,expected",
    [
        ("task export | cat", True),
        ("task export && task count", True),
        ("task export > /dev/null", True),
        ("task export > tasks.json", False),
        ("task export && task add unsafe", False),
        ("task add unsafe && task export", False),
        ("task export | task done", False),
    ],
)
def test_shell_composition_is_combined_centrally(
    check, command: str, expected: bool
) -> None:
    result = check(command)
    if expected:
        assert is_approved(result), f"Expected approved for: {command}"
    else:
        assert needs_confirmation(result), f"Expected confirmation for: {command}"
