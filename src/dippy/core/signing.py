"""Cryptographic signing for Dippy config files.

Uses ssh-keygen for sign/verify operations. Algorithm-agnostic — works with
any SSH key type (ed25519, rsa, ecdsa, etc.).
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

NAMESPACE = "dippy"
DEFAULT_IDENTITY = "dippy-user"
DEFAULT_ALLOWED_SIGNERS = Path.home() / ".dippy" / "allowed_signers"
DEFAULT_SIGNING_KEY_PUB = Path.home() / ".dippy" / "signing-key.pub"
DEFAULT_SSH_KEY = Path.home() / ".ssh" / "id_ed25519"

# Timeouts: signing/setup can involve agent round-trips, verification is local
_TIMEOUT_SIGN = 5
_TIMEOUT_VERIFY = 2


def sig_path_for(data_path: Path) -> Path:
    """Return the signature path for a data file.

    ssh-keygen appends '.sig' to the filename, so .dippy -> .dippy.sig.
    Can't use Path.with_suffix() here — it treats .dippy as an extension
    and would produce .sig instead of .dippy.sig.
    """
    return Path(str(data_path) + ".sig")


class SigningError(Exception):
    """Raised when a signing operation fails."""


class SigningProvider(ABC):
    """Abstract interface for signing operations."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the signing tool is available on this system."""

    @abstractmethod
    def extract_public_key(self, key_path: Path) -> str:
        """Read the public key string from a key file (.pub or private key)."""

    @abstractmethod
    def sign(
        self,
        key_path: Path,
        data_path: Path,
        namespace: str = NAMESPACE,
    ) -> None:
        """Sign data_path. Writes signature to data_path + '.sig'."""

    @abstractmethod
    def verify(
        self,
        allowed_signers_path: Path,
        identity: str,
        data_path: Path,
        sig_path: Path,
        namespace: str = NAMESPACE,
    ) -> bool:
        """Verify signature. Returns True if valid, False if invalid."""


class SSHKeygenProvider(SigningProvider):
    """Default provider — shells out to ssh-keygen."""

    def is_available(self) -> bool:
        return shutil.which("ssh-keygen") is not None

    def extract_public_key(self, key_path: Path) -> str:
        """Extract public key string from a key file.

        For .pub files, reads the content directly.
        For private keys, runs ssh-keygen -y -f to extract the public key.
        """
        if key_path.suffix == ".pub":
            try:
                return key_path.read_text().strip()
            except OSError as e:
                raise SigningError(f"cannot read public key {key_path}: {e}") from None

        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(key_path)],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SIGN,
        )
        if result.returncode != 0:
            raise SigningError(
                f"failed to extract public key from {key_path}: {result.stderr.strip()}"
            )
        return result.stdout.strip()

    def sign(
        self,
        key_path: Path,
        data_path: Path,
        namespace: str = NAMESPACE,
    ) -> None:
        """Sign data_path. ssh-keygen writes the signature to data_path + '.sig'."""
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key_path),
                "-n",
                namespace,
                str(data_path),
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SIGN,
        )
        if result.returncode != 0:
            raise SigningError(f"signing failed: {result.stderr.strip()}")

    def verify(
        self,
        allowed_signers_path: Path,
        identity: str,
        data_path: Path,
        sig_path: Path,
        namespace: str = NAMESPACE,
    ) -> bool:
        try:
            data = data_path.read_bytes()
        except OSError as e:
            raise SigningError(f"cannot read data file {data_path}: {e}") from None

        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers_path),
                "-I",
                identity,
                "-n",
                namespace,
                "-s",
                str(sig_path),
            ],
            input=data,
            capture_output=True,
            timeout=_TIMEOUT_VERIFY,
        )
        return result.returncode == 0


def get_provider(name: str = "ssh-keygen") -> SigningProvider:
    """Factory — returns the named provider or raises."""
    if name == "ssh-keygen":
        return SSHKeygenProvider()
    raise SigningError(f"unknown signing provider: {name}")
