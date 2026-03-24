"""Tests for the signing provider."""

from __future__ import annotations

import subprocess

import pytest

from dippy.core.signing import (
    NAMESPACE,
    SSHKeygenProvider,
    SigningError,
    get_provider,
    sig_path_for,
)


@pytest.fixture
def provider():
    return SSHKeygenProvider()


@pytest.fixture
def ssh_key(tmp_path):
    """Generate a temporary ed25519 SSH key pair. Returns (private_key, public_key)."""
    key_path = tmp_path / "test_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-q"],
        check=True,
    )
    return key_path, key_path.with_suffix(".pub")


@pytest.fixture
def ssh_key_alt(tmp_path):
    """Generate a second SSH key pair (different from ssh_key)."""
    key_path = tmp_path / "alt_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-q"],
        check=True,
    )
    return key_path, key_path.with_suffix(".pub")


@pytest.fixture
def allowed_signers(tmp_path, ssh_key):
    """Create an allowed_signers file from the test key."""
    _, pub_key = ssh_key
    pub_key_text = pub_key.read_text().strip()
    signers_path = tmp_path / "allowed_signers"
    signers_path.write_text(f"dippy-user {pub_key_text}\n")
    return signers_path


class TestSigPathFor:
    def test_normal_file(self, tmp_path):
        assert sig_path_for(tmp_path / "data.txt") == tmp_path / "data.txt.sig"

    def test_dotfile(self, tmp_path):
        """Critical: .dippy -> .dippy.sig, NOT .sig."""
        assert sig_path_for(tmp_path / ".dippy") == tmp_path / ".dippy.sig"


class TestSSHKeygenProvider:
    def test_is_available(self, provider):
        assert provider.is_available() is True

    def test_extract_public_key_from_pub_file(self, provider, ssh_key):
        _, pub_key = ssh_key
        result = provider.extract_public_key(pub_key)
        assert result.startswith("ssh-ed25519 ")

    def test_extract_public_key_from_private_key(self, provider, ssh_key):
        priv_key, pub_key = ssh_key
        result = provider.extract_public_key(priv_key)
        expected = pub_key.read_text().strip()
        # ssh-keygen -y output may not include the comment, so compare key part
        assert result.split()[1] == expected.split()[1]

    def test_extract_public_key_missing_file(self, provider, tmp_path):
        with pytest.raises(SigningError, match="cannot read"):
            provider.extract_public_key(tmp_path / "nonexistent.pub")

    def test_sign_creates_sig_file(self, provider, ssh_key, tmp_path):
        priv_key, _ = ssh_key
        data_path = tmp_path / "data.txt"
        data_path.write_text("hello world")

        provider.sign(priv_key, data_path)
        sig_path = sig_path_for(data_path)
        assert sig_path.exists()
        assert "SIGNATURE" in sig_path.read_text()

    def test_sign_with_pub_key_and_agent(self, provider, ssh_key, tmp_path):
        """Signing with .pub key requires ssh-agent; skip if not available."""
        _, pub_key = ssh_key
        data_path = tmp_path / "data.txt"
        data_path.write_text("test content")

        try:
            provider.sign(pub_key, data_path)
        except SigningError:
            pytest.skip("ssh-agent not available")

    def test_verify_valid_signature(self, provider, ssh_key, allowed_signers, tmp_path):
        priv_key, _ = ssh_key
        data_path = tmp_path / "config.txt"
        data_path.write_text("allow ls\nallow git *\n")

        provider.sign(priv_key, data_path)
        sig_path = sig_path_for(data_path)
        assert provider.verify(allowed_signers, "dippy-user", data_path, sig_path)

    def test_verify_tampered_content(self, provider, ssh_key, allowed_signers, tmp_path):
        priv_key, _ = ssh_key
        data_path = tmp_path / "config.txt"
        data_path.write_text("allow ls\n")

        provider.sign(priv_key, data_path)
        sig_path = sig_path_for(data_path)

        # Tamper with content
        data_path.write_text("allow rm -rf /\n")
        assert not provider.verify(allowed_signers, "dippy-user", data_path, sig_path)

    def test_verify_wrong_key(self, provider, ssh_key, ssh_key_alt, tmp_path):
        priv_key, _ = ssh_key
        _, alt_pub = ssh_key_alt

        data_path = tmp_path / "config.txt"
        data_path.write_text("allow ls\n")
        provider.sign(priv_key, data_path)
        sig_path = sig_path_for(data_path)

        # Create allowed_signers with the alt key only
        alt_signers = tmp_path / "alt_signers"
        alt_signers.write_text(f"dippy-user {alt_pub.read_text().strip()}\n")

        assert not provider.verify(alt_signers, "dippy-user", data_path, sig_path)

    def test_verify_missing_data_file(self, provider, allowed_signers, tmp_path):
        with pytest.raises(SigningError, match="cannot read data file"):
            provider.verify(
                allowed_signers,
                "dippy-user",
                tmp_path / "nonexistent",
                tmp_path / "nonexistent.sig",
            )

    def test_sign_custom_namespace(self, provider, ssh_key, allowed_signers, tmp_path):
        priv_key, _ = ssh_key
        data_path = tmp_path / "data.txt"
        data_path.write_text("test")

        provider.sign(priv_key, data_path, namespace="custom-ns")
        sig_path = sig_path_for(data_path)
        # Verify with matching namespace succeeds
        assert provider.verify(
            allowed_signers, "dippy-user", data_path, sig_path, namespace="custom-ns"
        )
        # Verify with wrong namespace fails
        assert not provider.verify(
            allowed_signers, "dippy-user", data_path, sig_path, namespace="wrong-ns"
        )


class TestGetProvider:
    def test_default_provider(self):
        p = get_provider()
        assert isinstance(p, SSHKeygenProvider)

    def test_explicit_ssh_keygen(self):
        p = get_provider("ssh-keygen")
        assert isinstance(p, SSHKeygenProvider)

    def test_unknown_provider(self):
        with pytest.raises(SigningError, match="unknown signing provider"):
            get_provider("gpg")
