"""Optional encrypted credential cache for CloudGuard.

Per prompt spec §E: If user enables caching (--cache), persist encrypted
credentials to ~/.cloudguard/creds.enc using user-supplied passphrase.
Implementation requirements:
- Strong KDF (PBKDF2) with safe iterations
- AES-GCM authenticated encryption
- OS file permissions (600)
- Default: no caching

SECURITY: This module is entirely opt-in. By default, CloudGuard never
caches credentials.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Cryptography is an optional dependency for credential caching
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


CLOUDGUARD_DIR = Path.home() / ".cloudguard"
CACHE_FILE = CLOUDGUARD_DIR / "creds.enc"
PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "Credential caching requires the 'cryptography' package.\n"
            "Install it: pip install cryptography"
        )
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def save_encrypted_credentials(
    creds: dict[str, str],
    passphrase: str,
) -> Path:
    """Encrypt and save credentials to ~/.cloudguard/creds.enc.

    Args:
        creds: Dictionary with AccessKeyId, SecretAccessKey, SessionToken, Expiration.
        passphrase: User-supplied passphrase for encryption.

    Returns:
        Path to the encrypted cache file.
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package required for credential caching")

    # Generate random salt and nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    plaintext = json.dumps(creds).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Store salt + nonce + ciphertext
    CLOUDGUARD_DIR.mkdir(parents=True, exist_ok=True)

    payload = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iterations": PBKDF2_ITERATIONS,
    }

    CACHE_FILE.write_text(json.dumps(payload), encoding="utf-8")

    # Set file permissions to 600 (owner read/write only)
    try:
        os.chmod(CACHE_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        logger.warning("Could not set file permissions on %s", CACHE_FILE)

    logger.info("Cached encrypted credentials to %s", CACHE_FILE)
    return CACHE_FILE


def load_encrypted_credentials(passphrase: str) -> dict[str, str] | None:
    """Load and decrypt credentials from ~/.cloudguard/creds.enc.

    Args:
        passphrase: User-supplied passphrase for decryption.

    Returns:
        Dictionary with credentials, or None if cache doesn't exist.
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package required for credential caching")

    if not CACHE_FILE.exists():
        return None

    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        salt = base64.b64decode(payload["salt"])
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])

        key = _derive_key(passphrase, salt)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))

    except Exception as e:
        logger.warning("Failed to decrypt credential cache: %s", e)
        return None


def clear_cache() -> bool:
    """Delete the cached credentials file.

    Returns:
        True if cache was deleted, False if it didn't exist.
    """
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()
        logger.info("Credential cache cleared: %s", CACHE_FILE)
        return True
    return False
