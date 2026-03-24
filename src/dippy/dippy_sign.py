#!/usr/bin/env python3
"""dippy-sign — manage cryptographic signatures for Dippy config files."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from dippy.core.signing import (
    DEFAULT_ALLOWED_SIGNERS,
    DEFAULT_IDENTITY,
    DEFAULT_SIGNING_KEY_PUB,
    DEFAULT_SSH_KEY,
    NAMESPACE,
    SigningError,
    get_provider,
    sig_path_for,
)


def _resolve_signing_key(explicit: str | None) -> Path:
    """Resolve which key to use for signing.

    Order:
    1. --key-file <path> (explicit override)
    2. ~/.dippy/signing-key.pub (agent-based signing)
    3. ~/.ssh/id_ed25519 (direct signing fallback)
    """
    if explicit:
        path = Path(explicit).expanduser()
        if not path.exists():
            print(f"error: key file not found: {path}", file=sys.stderr)
            raise SystemExit(1)
        return path

    if DEFAULT_SIGNING_KEY_PUB.exists():
        return DEFAULT_SIGNING_KEY_PUB

    if DEFAULT_SSH_KEY.exists():
        return DEFAULT_SSH_KEY

    print(
        "error: no signing key found\n"
        "\n"
        "Options:\n"
        "  1. Run `dippy-sign init <your-key.pub>` to set up signing\n"
        "  2. Pass --key-file <path> explicitly\n"
        "  3. Ensure ~/.ssh/id_ed25519 exists",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _find_dippy_config() -> Path:
    """Find .dippy in cwd or error."""
    config = Path.cwd() / ".dippy"
    if not config.is_file():
        print("error: no .dippy file found in current directory", file=sys.stderr)
        raise SystemExit(1)
    return config


def _file_hash(path: Path) -> str:
    """Return SHA-256 hex digest of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_init(args: argparse.Namespace) -> None:
    """Set up signing: copy public key, create allowed_signers, enable enforcement."""
    pub_key_file = Path(args.pub_key_file).expanduser()
    if not pub_key_file.exists():
        print(f"error: public key file not found: {pub_key_file}", file=sys.stderr)
        raise SystemExit(1)

    provider = get_provider()
    if not provider.is_available():
        print("error: ssh-keygen not found", file=sys.stderr)
        raise SystemExit(1)

    # Read the public key
    pub_key = provider.extract_public_key(pub_key_file)

    dippy_dir = DEFAULT_SIGNING_KEY_PUB.parent
    dippy_dir.mkdir(parents=True, exist_ok=True)

    # Check for existing setup
    if not args.force:
        existing = []
        if DEFAULT_SIGNING_KEY_PUB.exists():
            existing.append(str(DEFAULT_SIGNING_KEY_PUB))
        if DEFAULT_ALLOWED_SIGNERS.exists():
            existing.append(str(DEFAULT_ALLOWED_SIGNERS))
        if existing:
            print(
                "error: signing already configured (found "
                + ", ".join(existing)
                + ")\n"
                "Use --force to overwrite.",
                file=sys.stderr,
            )
            raise SystemExit(1)

    # Copy public key
    DEFAULT_SIGNING_KEY_PUB.write_text(pub_key + "\n")
    print(f"  Created {DEFAULT_SIGNING_KEY_PUB}")

    # Create allowed_signers
    allowed_line = f"{DEFAULT_IDENTITY} {pub_key}\n"
    DEFAULT_ALLOWED_SIGNERS.write_text(allowed_line)
    print(f"  Created {DEFAULT_ALLOWED_SIGNERS}")

    # Append require-signatures to user config
    user_config = dippy_dir / "config"
    needs_setting = True
    if user_config.exists():
        content = user_config.read_text()
        if "require-signatures" in content or "require_signatures" in content:
            needs_setting = False

    if needs_setting:
        with open(user_config, "a") as f:
            f.write("\nset require-signatures true\n")
        print(f"  Added 'set require-signatures true' to {user_config}")

    print("\nSigning configured. Next steps:")
    print("  1. cd to your project with a .dippy file")
    print("  2. Run `dippy-sign sign` to sign it")


def cmd_sign(args: argparse.Namespace) -> None:
    """Sign the .dippy config in the current directory."""
    config_path = _find_dippy_config()
    key_path = _resolve_signing_key(args.key_file)

    provider = get_provider()
    if not provider.is_available():
        print("error: ssh-keygen not found", file=sys.stderr)
        raise SystemExit(1)

    try:
        provider.sign(key_path, config_path, NAMESPACE)
    except SigningError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1)

    sig_path = sig_path_for(config_path)
    digest = _file_hash(config_path)
    print(f"Signed .dippy (sha256:{digest[:16]}...)")
    print(f"  Signature: {sig_path}")
    print(f"  Key: {key_path}")


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify the .dippy signature in the current directory."""
    config_path = _find_dippy_config()
    sig_path = sig_path_for(config_path)

    if not sig_path.exists():
        print("FAIL: .dippy.sig not found", file=sys.stderr)
        raise SystemExit(1)

    if not DEFAULT_ALLOWED_SIGNERS.exists():
        print(
            f"FAIL: allowed_signers not found ({DEFAULT_ALLOWED_SIGNERS})",
            file=sys.stderr,
        )
        raise SystemExit(1)

    provider = get_provider()
    if not provider.is_available():
        print("error: ssh-keygen not found", file=sys.stderr)
        raise SystemExit(1)

    try:
        valid = provider.verify(
            DEFAULT_ALLOWED_SIGNERS,
            DEFAULT_IDENTITY,
            config_path,
            sig_path,
            NAMESPACE,
        )
    except SigningError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        raise SystemExit(1)

    if valid:
        print("OK: signature valid")
    else:
        print("FAIL: signature invalid", file=sys.stderr)
        raise SystemExit(1)


def cmd_status(args: argparse.Namespace) -> None:
    """Show signing status for the current directory."""
    config_path = Path.cwd() / ".dippy"
    sig_path = sig_path_for(config_path)

    # .dippy exists?
    if config_path.is_file():
        print(f"Config:     {config_path}")
    else:
        print("Config:     not found")

    # .dippy.sig exists?
    if sig_path.is_file():
        print(f"Signature:  {sig_path}")
    else:
        print("Signature:  not found")

    # Signing key
    if DEFAULT_SIGNING_KEY_PUB.exists():
        print(f"Signing key: {DEFAULT_SIGNING_KEY_PUB}")
    elif DEFAULT_SSH_KEY.exists():
        print(f"Signing key: {DEFAULT_SSH_KEY} (fallback)")
    else:
        print("Signing key: not configured")

    # require-signatures enabled?
    user_config = DEFAULT_SIGNING_KEY_PUB.parent / "config"
    require_sig = False
    if user_config.exists():
        content = user_config.read_text()
        for line in content.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("set") and "require" in stripped and "signature" in stripped:
                require_sig = "true" in stripped
    print(f"Enforcement: {'enabled' if require_sig else 'disabled'}")

    # Trusted signers
    if DEFAULT_ALLOWED_SIGNERS.exists():
        lines = [
            l.strip()
            for l in DEFAULT_ALLOWED_SIGNERS.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        print(f"Trusted signers ({len(lines)}):")
        for line in lines:
            parts = line.split(None, 2)
            identity = parts[0] if parts else "?"
            key_type = parts[1] if len(parts) > 1 else "?"
            print(f"  {identity} ({key_type})")
    else:
        print("Trusted signers: none (allowed_signers not found)")

    # Verification status
    if config_path.is_file() and sig_path.is_file() and DEFAULT_ALLOWED_SIGNERS.exists():
        provider = get_provider()
        if provider.is_available():
            try:
                valid = provider.verify(
                    DEFAULT_ALLOWED_SIGNERS,
                    DEFAULT_IDENTITY,
                    config_path,
                    sig_path,
                    NAMESPACE,
                )
                print(f"Verification: {'PASS' if valid else 'FAIL'}")
            except SigningError as e:
                print(f"Verification: error ({e})")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dippy-sign",
        description="Manage cryptographic signatures for Dippy config files.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # init
    init_parser = subparsers.add_parser(
        "init", help="Set up config signing with a public key"
    )
    init_parser.add_argument(
        "pub_key_file", help="Path to your SSH public key (.pub file)"
    )
    init_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing setup"
    )

    # sign
    sign_parser = subparsers.add_parser("sign", help="Sign the .dippy config")
    sign_parser.add_argument(
        "--key-file", help="Path to signing key (overrides default resolution)"
    )

    # verify
    subparsers.add_parser("verify", help="Verify the .dippy config signature")

    # status
    subparsers.add_parser("status", help="Show signing status")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        raise SystemExit(1)

    commands = {
        "init": cmd_init,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "status": cmd_status,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
