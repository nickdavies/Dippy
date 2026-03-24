<p align="center">
  <img src="images/dippy.gif" width="200">
</p>

<h1 align="center">🐤 Dippy</h1>
<p align="center"><em>Because <code>ls</code> shouldn't need approval</em></p>

---

> **Stop the permission fatigue.** Claude Code asks for approval on every `ls`, `git status`, and `cat` - destroying your flow state. You check Slack, come back, and your assistant's just sitting there waiting.

Dippy is a shell command hook that auto-approves safe commands while still prompting for anything destructive. When it blocks, your custom deny messages can steer the AI back on track—no wasted turns. Get up to **40% faster development** without disabling permissions entirely.

Works with **Claude Code**, **Cursor**, and **Gemini CLI**.

Built on [Parable](https://github.com/ldayton/Parable), our own hand-written bash parser—no external dependencies, just pure Python. 14,000+ tests between the two.

***Example: rejecting unsafe operation in a chain***

![Screenshot](images/terraform-apply.png)

***Example: rejecting a command with advice, so Claude can keep going***

![Deny with message](images/deny-with-message.png)

## ✅ What gets approved

- **Complex pipelines**: `ps aux | grep python | awk '{print $2}' | head -10`
- **Chained reads**: `git status && git log --oneline -5 && git diff --stat`
- **Cloud inspection**: `aws ec2 describe-instances --filters "Name=tag:Environment,Values=prod"`
- **Container debugging**: `docker logs --tail 100 api-server 2>&1 | grep ERROR`
- **Safe redirects**: `grep -r "TODO" src/ 2>/dev/null`, `ls &>/dev/null`
- **Command substitution**: `ls $(pwd)`, `git diff foo-$(date).txt`

![Safe command substitution](images/safe-cmd-sub.png)

## 🚫 What gets blocked

- **Subshell injection**: `git $(echo rm) foo.txt`, `echo $(rm -rf /)`
- **Subtle file writes**: `curl https://example.com > script.sh`, `tee output.log`
- **Hidden mutations**: `git stash drop`, `npm unpublish`, `brew unlink`
- **Cloud danger**: `aws s3 rm s3://bucket --recursive`, `kubectl delete pod`
- **Destructive chains**: `rm -rf node_modules && npm install` (blocks the whole thing)

![Redirect blocked](images/redirect.png)

---

## Installation

### Homebrew (recommended)

```bash
brew tap ldayton/dippy
brew install dippy
```

### Manual

```bash
git clone https://github.com/ldayton/Dippy.git
```

### Configure

#### Claude Code

Add to `~/.claude/settings.json` (or use `/hooks` interactively):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "dippy" }]
      }
    ]
  }
}
```

#### Cursor

Cursor currently gives its two shell hook types different permission behavior.
Choose the hook based on whether your policy depends on an approval prompt.

Use `preToolUse` when Dippy's `allow`/`deny` decisions are sufficient:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      { "matcher": "Shell", "command": "dippy" }
    ]
  }
}
```

The `Shell` matcher limits Dippy to shell invocations. Dippy reads the command
from `tool_input.command`; a non-shell tool, malformed `tool_input`, or missing
command produces an empty JSON response rather than a Dippy permission decision.

Current Cursor accepts `permission: "ask"` from `preToolUse` but does not enforce
it by displaying a confirmation prompt. It behaves as no enforced Dippy decision,
like Dippy's `{}` passthrough response. Do **not** use `preToolUse` where commands
classified as `ask` must prompt before execution.

Use `beforeShellExecution` when retaining Cursor's approval prompt is required:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "dippy" }
    ]
  }
}
```

Dippy reads this hook's top-level `command`. Current Cursor enforces Dippy's
`deny`, but a Dippy `allow` does not skip Cursor's own approval flow; `allow` and
`ask` can therefore still result in Cursor prompting. This preserves prompting
for commands that require it, at the cost of not reliably auto-approving safe
commands.

Dippy auto-detects both Cursor payloads. You can instead force the mode with
`dippy --cursor` or `DIPPY_CURSOR=1`. Cursor responses use `permission` with an
`allow`, `ask`, or `deny` value, and logs go to
`~/.cursor/hook-approvals.log`.

These are observed current-Cursor limits, not guarantees of the hook protocol.
Permission and sandbox settings may also affect execution. Dippy's tests verify
payload parsing and emitted JSON; verify end-to-end behavior with the Cursor
version and settings you deploy.

If you installed manually, use the full path instead: `/path/to/Dippy/bin/dippy-hook`

---

## Configuration

Dippy is highly customizable. Beyond simple allow/deny rules, you can attach messages that steer the AI back on track when it goes astray—no wasted turns.

```
deny python "Use uv run python, which runs in project environment"
deny rm -rf "Use trash instead"
deny-redirect **/.env* "Never write secrets, ask me to do it"
```

Dippy reads config from `~/.dippy/config` (global) and `.dippy` in your project root.

### Python symbol allowlisting

Use `python-allow-symbol module.symbol` to permit one exact symbol from a module
that Python static analysis would otherwise reject:

```text
python-allow-symbol sys.stdin
```

The allowance applies only to an absolute, exact-module import such as
`from sys import stdin`. Aliases are permitted (`from sys import stdin as input`),
but `import sys`, wildcard imports, relative imports, symbols not listed in the
configuration, and imports from a different module remain subject to the normal
Python safety checks. Every name in a multi-name import must be allowed.

`python-deny-module` takes precedence over symbol allowances, including when the
directives come from different merged configuration scopes. A
`python-allow-module` remains a module-wide allowance and therefore does not
restrict that module to listed symbols. Existing module-directive semantics are
unchanged: an exact `python-allow-module` entry overrides an exact
`python-deny-module` entry.

This directive is a trust decision, not a Python sandbox. Importing a symbol can
execute the module's top-level code, and using the imported object may have side
effects that static analysis cannot prove safe. Only allow symbols from modules
and implementations you trust. Other AST safety checks still apply after the
import is accepted.

**Full documentation:** [Dippy Wiki](https://github.com/ldayton/Dippy/wiki)

---

## Extensions

Dippy can do more than filter shell commands. See the [wiki](https://github.com/ldayton/Dippy/wiki) for additional capabilities.

### External CLI handlers

Python packages installed in the same environment as Dippy can add command
handlers through the `dippy.handlers` entry point group:

```toml
[project]
name = "dippy-mytools"
dependencies = ["dippy>=0.2.7"]

[project.entry-points."dippy.handlers"]
mytools = "dippy_mytools.handler"
```

The entry point target may be a module, as above, or an object such as
`dippy_mytools.handlers:MYTOOLS_HANDLER`. The resolved module or object must
provide this interface:

```python
from dippy.cli import Classification, HandlerContext

COMMANDS = ["mytools"]


def classify(ctx: HandlerContext) -> Classification:
    if len(ctx.tokens) > 1 and ctx.tokens[1] in {"get", "list", "status"}:
        return Classification("allow", description=" ".join(ctx.tokens[:2]))
    return Classification("ask", description="mytools")
```

`COMMANDS` must be a non-empty list or tuple of non-empty strings, and
`classify` must be callable. A handler receives the current `tokens`, `config`,
and `word_has_expansions` through `HandlerContext`. Dippy loads each entry point
once per process, skips plugins that fail to load or do not satisfy this
contract, and defaults to asking when a plugin fails or returns malformed data
at runtime. An external plugin cannot replace a built-in handler. If multiple
plugins claim the same command, the first entry point returned by Python's
package metadata wins; that order is not guaranteed, so packages must not rely
on it.

> **Security:** Handler plugins are trusted code. Installing one executes
> arbitrary Python in Dippy's process, and a plugin can approve commands.
> Built-in precedence only prevents command-name replacement; it is not a
> sandbox or a security boundary between Dippy and installed plugins.

---

## Uninstall

Remove the hook entry from `~/.claude/settings.json` or `~/.cursor/hooks.json`, then:

```bash
brew uninstall dippy  # if installed via Homebrew
```
