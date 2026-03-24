<p align="center">
  <img src="images/dippy.gif" width="200">
</p>

<h1 align="center">🐤 Dippy</h1>
<p align="center"><em>Because <code>ls</code> shouldn't need approval</em></p>

---

> **Stop the permission fatigue.** Claude Code asks for approval on every `ls`, `git status`, and `cat` - destroying your flow state. You check Slack, come back, and your assistant's just sitting there waiting.

Dippy is a shell command hook that auto-approves safe commands while still prompting for anything destructive. When it blocks, your custom deny messages can steer Claude back on track—no wasted turns. Get up to **40% faster development** without disabling permissions entirely.

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

**Full documentation:** [Dippy Wiki](https://github.com/ldayton/Dippy/wiki)

---

## Extensions

Dippy can do more than filter shell commands. See the [wiki](https://github.com/ldayton/Dippy/wiki) for additional capabilities.

---

## Config Signing

Dippy's project-level `.dippy` files can grant additional permissions to AI agents. An agent could modify or create `.dippy` to be more permissive. Cryptographic signing makes unauthorized writes meaningless — Dippy refuses to honor unsigned or tampered configs.

### Quick Start

```bash
# One-time setup: register your SSH public key for signing
dippy-sign init ~/.ssh/id_ed25519.pub

# In your project directory, sign the .dippy config
dippy-sign sign

# Verify it worked
dippy-sign verify
```

`dippy-sign init` does three things:
1. Copies your public key to `~/.dippy/signing-key.pub` (so `dippy-sign sign` knows which key to use)
2. Creates `~/.dippy/allowed_signers` (so Dippy can verify signatures)
3. Adds `set require-signatures true` to `~/.dippy/config` (enables enforcement)

### Signing with SSH Agent

If you use an SSH agent, `dippy-sign sign` uses `~/.dippy/signing-key.pub` to tell `ssh-keygen` which key to request from the agent. No private key is ever stored in `~/.dippy/`.

### Signing without an Agent

Pass the private key directly:

```bash
dippy-sign sign --key-file ~/.ssh/id_ed25519
```

### How Verification Works

When Dippy loads a project `.dippy` file:

1. If `.dippy.sig` exists next to `.dippy`, Dippy verifies the signature against `~/.dippy/allowed_signers`
2. If the signature is invalid or tampered, **all commands are denied**
3. If `require-signatures` is enabled and no `.dippy.sig` exists, **all commands are denied**
4. If `require-signatures` is disabled and no `.dippy.sig` exists, Dippy works as normal

### Recommended: Deny Rules for Config Files

Prevent the AI from modifying signing-related files. Add to `~/.claude/settings.json`:

```json
{
  "deny": [
    "Edit ~/.dippy/**",
    "Write ~/.dippy/**",
    "Edit **/.dippy",
    "Write **/.dippy",
    "Edit **/.dippy.sig",
    "Write **/.dippy.sig"
  ]
}
```

### Commands

| Command | Description |
|---------|-------------|
| `dippy-sign init <key.pub>` | Set up signing with a public key |
| `dippy-sign sign` | Sign `.dippy` in current directory |
| `dippy-sign verify` | Verify `.dippy` signature |
| `dippy-sign status` | Show signing configuration and status |

---

## Uninstall

Remove the hook entry from `~/.claude/settings.json`, then:

```bash
brew uninstall dippy  # if installed via Homebrew
```
