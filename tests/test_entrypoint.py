"""Tests for bin/dippy-hook entry point."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DIPPY_HOOK = REPO_ROOT / "bin" / "dippy-hook"
# Use system Python to avoid venv masking import issues
SYSTEM_PYTHON = "/usr/bin/python3"


def get_decision(output: dict) -> str | None:
    """Extract decision from hook output format."""
    return output.get("hookSpecificOutput", {}).get("permissionDecision")


def run_hook(
    input_data: object | None = None,
    via_symlink: bool = False,
    use_system_python: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run dippy-hook with given input, optionally via a symlink."""
    if via_symlink:
        # Create a temporary symlink to test symlink resolution
        with tempfile.TemporaryDirectory() as tmpdir:
            symlink_path = Path(tmpdir) / "dippy"
            symlink_path.symlink_to(DIPPY_HOOK)
            return _run(symlink_path, input_data, use_system_python, env)
    return _run(DIPPY_HOOK, input_data, use_system_python, env)


def _run(
    script: Path,
    input_data: object | None,
    use_system_python: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Execute the script with input."""
    if input_data is None:
        stdin_bytes = b""
    elif isinstance(input_data, str):
        stdin_bytes = input_data.encode()
    else:
        stdin_bytes = json.dumps(input_data).encode()

    python = SYSTEM_PYTHON if use_system_python else sys.executable
    return subprocess.run(
        [python, str(script)],
        input=stdin_bytes,
        capture_output=True,
        timeout=10,
        env=env,
    )


class TestSymlinkResolution:
    """Test that dippy-hook works when invoked via symlink (Homebrew scenario)."""

    def test_direct_invocation(self):
        """Baseline: direct invocation works."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        result = run_hook(input_data, via_symlink=False)
        assert result.returncode == 0, f"stderr: {result.stderr.decode()}"
        output = json.loads(result.stdout)
        assert get_decision(output) == "allow"

    def test_symlink_invocation(self):
        """Critical: invocation via symlink must also work.

        Uses system Python to ensure we're testing the script's path resolution,
        not relying on dippy being installed in the venv.
        """
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        result = run_hook(input_data, via_symlink=True, use_system_python=True)
        assert result.returncode == 0, f"stderr: {result.stderr.decode()}"
        output = json.loads(result.stdout)
        assert get_decision(output) == "allow"

    def test_nested_symlink_invocation(self):
        """Symlink in deeply nested unrelated path (simulates Homebrew Cellar)."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate: /opt/homebrew/bin/dippy -> /opt/homebrew/Cellar/dippy/0.1/libexec/bin/dippy-hook
            nested = Path(tmpdir) / "opt" / "homebrew" / "bin"
            nested.mkdir(parents=True)
            symlink_path = nested / "dippy"
            symlink_path.symlink_to(DIPPY_HOOK)

            stdin_bytes = json.dumps(input_data).encode()
            result = subprocess.run(
                [SYSTEM_PYTHON, str(symlink_path)],
                input=stdin_bytes,
                capture_output=True,
                timeout=10,
            )
            assert result.returncode == 0, f"stderr: {result.stderr.decode()}"
            output = json.loads(result.stdout)
            assert get_decision(output) == "allow"


class TestEndToEnd:
    """End-to-end tests for JSON input/output."""

    def test_allow_safe_command(self):
        """Safe commands return allow decision."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "git status"}}
        result = run_hook(input_data)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert get_decision(output) == "allow"

    def test_ask_unknown_command(self):
        """Unknown commands return ask decision."""
        input_data = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        result = run_hook(input_data)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert get_decision(output) == "ask"

    def test_non_bash_tool_passthrough(self):
        """Non-Bash tools should pass through (allow)."""
        input_data = {"tool_name": "Read", "tool_input": {"path": "/etc/passwd"}}
        result = run_hook(input_data)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        # Non-Bash tools return empty object (passthrough)
        assert output == {}


class TestCursorPreToolUse:
    """End-to-end tests for Cursor's preToolUse payload."""

    def test_safe_shell_command_is_allowed(self, cursor_pretooluse_input, tmp_path):
        input_data = cursor_pretooluse_input("git status")

        output = self._run_isolated(input_data, tmp_path)

        assert output["permission"] == "allow"

    def test_unknown_shell_command_asks(self, cursor_pretooluse_input, tmp_path):
        input_data = cursor_pretooluse_input("rm -rf /")

        output = self._run_isolated(input_data, tmp_path)

        assert output["permission"] == "ask"

    def test_configured_shell_command_is_denied(
        self, cursor_pretooluse_input, tmp_path
    ):
        config = tmp_path / "config"
        config.write_text('deny rm -rf /* "never remove the root filesystem"\n')
        input_data = cursor_pretooluse_input("rm -rf /")

        output = self._run_isolated(input_data, tmp_path, config=config)

        assert output["permission"] == "deny"
        assert "never remove the root filesystem" in output["agent_message"]

    def test_malformed_tool_input_passes_through(
        self, cursor_pretooluse_input, tmp_path
    ):
        input_data = cursor_pretooluse_input(tool_input=["not", "an", "object"])

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_missing_command_passes_through(self, cursor_pretooluse_input, tmp_path):
        input_data = cursor_pretooluse_input(tool_input={"cwd": ""})

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_missing_tool_name_passes_through(self, cursor_pretooluse_input, tmp_path):
        input_data = cursor_pretooluse_input()
        del input_data["tool_name"]

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_top_level_command_does_not_satisfy_pretooluse(
        self, cursor_pretooluse_input, tmp_path
    ):
        input_data = cursor_pretooluse_input()
        del input_data["tool_name"]
        del input_data["tool_input"]
        input_data["command"] = "git status"

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_non_shell_tool_passes_through(self, cursor_pretooluse_input, tmp_path):
        input_data = cursor_pretooluse_input(
            tool_name="Read", tool_input={"path": "/etc/passwd"}
        )

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_explicit_before_shell_execution_is_allowed(self, tmp_path):
        input_data = {
            "hook_event_name": "beforeShellExecution",
            "cursor_version": "test-version",
            "command": "git status",
            "cwd": str(tmp_path),
        }

        output = self._run_isolated(input_data, tmp_path)

        assert output["permission"] == "allow"

    def test_before_shell_execution_requires_top_level_command(
        self, cursor_pretooluse_input, tmp_path
    ):
        input_data = cursor_pretooluse_input()
        input_data["hook_event_name"] = "beforeShellExecution"

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_unsupported_command_event_passes_through(self, tmp_path):
        input_data = {
            "hook_event_name": "afterShellExecution",
            "cursor_version": "test-version",
            "command": "git status",
            "cwd": str(tmp_path),
        }

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_unsupported_tool_event_passes_through(
        self, cursor_pretooluse_input, tmp_path
    ):
        input_data = cursor_pretooluse_input()
        input_data["hook_event_name"] = "postToolUse"

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    def test_unsupported_tool_event_without_cursor_version_passes_through(
        self, cursor_pretooluse_input, tmp_path
    ):
        input_data = cursor_pretooluse_input()
        input_data["hook_event_name"] = "postToolUse"
        del input_data["cursor_version"]

        output = self._run_isolated(input_data, tmp_path)

        assert output == {}

    @staticmethod
    def _run_isolated(input_data, home: Path, config: Path | None = None) -> dict:
        env = os.environ.copy()
        env["HOME"] = str(home)
        if config is not None:
            env["DIPPY_CONFIG"] = str(config)
        else:
            env.pop("DIPPY_CONFIG", None)
        result = run_hook(input_data, env=env)
        assert result.returncode == 0, result.stderr.decode()
        return json.loads(result.stdout)


class TestModeRegression:
    """Ensure existing hook payloads retain their response formats."""

    def test_claude_bash(self, tmp_path):
        input_data = {"tool_name": "Bash", "tool_input": {"command": "git status"}}

        output = TestCursorPreToolUse._run_isolated(input_data, tmp_path)

        assert get_decision(output) == "allow"

    def test_gemini_shell(self, tmp_path):
        input_data = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git status"},
        }

        output = TestCursorPreToolUse._run_isolated(input_data, tmp_path)

        assert output["decision"] == "allow"

    def test_cursor_before_shell_execution(self, tmp_path):
        """Legacy event-less beforeShellExecution payload remains supported."""
        input_data = {"command": "git status", "cwd": str(tmp_path)}

        output = TestCursorPreToolUse._run_isolated(input_data, tmp_path)

        assert output["permission"] == "allow"

    def test_cursor_eventless_shell_tool(self, cursor_pretooluse_input, tmp_path):
        """Legacy event-less Shell payload remains supported."""
        input_data = cursor_pretooluse_input()
        del input_data["hook_event_name"]

        output = TestCursorPreToolUse._run_isolated(input_data, tmp_path)

        assert output["permission"] == "allow"


class TestErrorHandling:
    """Test graceful handling of bad input."""

    def test_invalid_json(self):
        """Malformed JSON should not crash."""
        result = run_hook("not valid json {{{")
        assert result.returncode == 0
        assert json.loads(result.stdout) == {}

    def test_empty_stdin(self):
        """Empty stdin should not crash."""
        result = run_hook(None)
        assert result.returncode == 0

    def test_non_object_json(self):
        """A valid JSON value that is not an object should pass through."""
        result = run_hook(["not", "an", "object"])
        assert result.returncode == 0
        assert json.loads(result.stdout) == {}

    def test_missing_tool_name(self):
        """Missing tool_name field should not crash."""
        result = run_hook({"tool_input": {"command": "ls"}})
        assert result.returncode == 0

    def test_missing_tool_input(self):
        """Missing tool_input field should not crash."""
        result = run_hook({"tool_name": "Bash"})
        assert result.returncode == 0
