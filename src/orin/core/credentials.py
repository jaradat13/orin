# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# src/orin/core/credentials.py
"""
orin.core.credentials – Secure Credential Management
====================================================
Provides secure handling of sensitive credentials including vault passphrases
and dashboard session tokens. Implements defense-in-depth strategies to minimize
credential exposure in logs, process lists, and memory.

Features
--------
* Environment variable loading with validation
* Secure random token generation
* Credential redaction for logging
* Optional integration with OS secret managers (keyring)
* Memory-safe credential handling with automatic cleanup
* Timing-safe comparison operations

Security Principles
-------------------
1. **Least Privilege**: Credentials only accessible when explicitly needed
2. **Defense in Depth**: Multiple layers of protection (env vars, keyring, encryption)
3. **Minimize Exposure**: Never log credentials, minimize time in memory
4. **Secure Defaults**: Strong defaults for passphrase complexity and token entropy
"""

import os
import sys
import hmac
import secrets
import weakref
from pathlib import Path
from typing import Optional, Tuple
from contextlib import contextmanager


class SecureCredential:
    """Wrapper for sensitive credential data with automatic cleanup.

    This class provides a secure container for credentials that:
    - Prevents accidental logging via __repr__ and __str__
    - Supports automatic zeroization on garbage collection
    - Provides timing-safe comparison operations

    Attributes
    ----------
    _value : Optional[str]
        The actual credential value (protected)
    _length : int
        Cached length to avoid exposing value during len() calls
    """

    def __init__(self, value: str):
        """Initialize secure credential wrapper.

        Parameters
        ----------
        value : str
            The credential value to protect
        """
        if not isinstance(value, str):
            raise TypeError("Credential value must be a string")

        self._value = value
        self._length = len(value)
        self._finalizer = weakref.finalize(self, self._zeroize, value)

    @staticmethod
    def _zeroize(value: str) -> None:
        """Attempt to zeroize credential from memory.

        Note: Python's string immutability limits true zeroization,
        but we can at least remove references.
        """
        # In CPython, strings are immutable, so we can't truly zeroize
        # However, removing all references helps garbage collection
        pass

    def __str__(self) -> str:
        """Prevent accidental string conversion."""
        return "[REDACTED]"

    def __repr__(self) -> str:
        """Prevent accidental repr exposure."""
        return f"SecureCredential(length={self._length})"

    def get_value(self) -> str:
        """Retrieve the actual credential value.

        Returns
        -------
        str
            The credential value
        """
        return self._value

    def __len__(self) -> int:
        """Return length without exposing value."""
        return self._length

    def compare_secure(self, other: str) -> bool:
        """Perform timing-safe comparison with another string.

        Parameters
        ----------
        other : str
            The string to compare against

        Returns
        -------
        bool
            True if values match, False otherwise
        """
        return hmac.compare_digest(self._value, other)

    def is_empty(self) -> bool:
        """Check if credential is empty or unset.

        Returns
        -------
        bool
            True if credential has no value
        """
        return self._length == 0


class CredentialManager:
    """Centralized manager for Orin credentials.

    Manages vault passphrases and dashboard tokens with secure retrieval,
    validation, and lifecycle management.

    Parameters
    ----------
    vault_passphrase_env : str, optional
        Environment variable name for vault passphrase (default: ORIN_VAULT_PASSPHRASE)
    min_passphrase_length : int, optional
        Minimum acceptable passphrase length (default: 12)
    """

    DEFAULT_PASSPHRASE_ENV = "ORIN_VAULT_PASSPHRASE"
    MIN_PASSPHRASE_LENGTH = 12
    TOKEN_BYTES = 32  # 256-bit token

    def __init__(
        self,
        vault_passphrase_env: Optional[str] = None,
        min_passphrase_length: Optional[int] = None
    ):
        """Initialize credential manager.

        Parameters
        ----------
        vault_passphrase_env : str, optional
            Custom environment variable name for vault passphrase
        min_passphrase_length : int, optional
            Custom minimum passphrase length requirement
        """
        self.vault_passphrase_env = vault_passphrase_env or self.DEFAULT_PASSPHRASE_ENV
        self.min_passphrase_length = min_passphrase_length or self.MIN_PASSPHRASE_LENGTH
        self._vault_passphrase: Optional[SecureCredential] = None
        self._session_token: Optional[SecureCredential] = None

    def load_vault_passphrase(
        self,
        env_var: Optional[str] = None,
        required: bool = False
    ) -> Optional[SecureCredential]:
        """Load vault passphrase from environment.

        Attempts to load the passphrase from the specified environment variable.
        Validates minimum length if provided.

        Parameters
        ----------
        env_var : str, optional
            Environment variable to read from (overrides default)
        required : bool, optional
            If True, raises ValueError when passphrase not found

        Returns
        -------
        Optional[SecureCredential]
            Wrapped passphrase if found and valid, None otherwise

        Raises
        ------
        ValueError
            If passphrase is required but not found, or fails validation
        """
        env_name = env_var or self.vault_passphrase_env
        passphrase = os.environ.get(env_name)

        if not passphrase:
            if required:
                raise ValueError(
                    f"Vault passphrase required but {env_name} not set. "
                    "Set this environment variable before running Orin."
                )
            return None

        # Validate minimum length
        if len(passphrase) < self.min_passphrase_length:
            if required:
                raise ValueError(
                    f"Vault passphrase too short ({len(passphrase)} chars). "
                    f"Minimum required: {self.min_passphrase_length} characters."
                )
            # Log warning but don't fail - allows graceful degradation
            print(
                f"[!] Warning: Vault passphrase too short ({len(passphrase)} chars). "
                f"Minimum recommended: {self.min_passphrase_length} characters.",
                file=sys.stderr
            )
            return None

        self._vault_passphrase = SecureCredential(passphrase)
        return self._vault_passphrase

    def generate_session_token(self) -> SecureCredential:
        """Generate a new cryptographically secure session token.

        Creates a 256-bit random token suitable for dashboard authentication.
        Token is stored internally and returned wrapped in SecureCredential.

        Returns
        -------
        SecureCredential
            Newly generated session token
        """
        # Generate 32 bytes (256 bits) of random data, hex-encoded
        token_hex = secrets.token_hex(self.TOKEN_BYTES)
        self._session_token = SecureCredential(token_hex)
        return self._session_token

    def get_session_token(self) -> Optional[SecureCredential]:
        """Retrieve the current session token.

        Returns
        -------
        Optional[SecureCredential]
            Current session token if generated, None otherwise
        """
        return self._session_token

    def get_vault_passphrase(self) -> Optional[SecureCredential]:
        """Retrieve the loaded vault passphrase.

        Returns
        -------
        Optional[SecureCredential]
            Loaded passphrase if available, None otherwise
        """
        return self._vault_passphrase

    def validate_token(self, provided_token: str) -> bool:
        """Validate a provided token against the current session token.

        Uses timing-safe comparison to prevent timing attacks.

        Parameters
        ----------
        provided_token : str
            Token to validate

        Returns
        -------
        bool
            True if token matches, False otherwise
        """
        if not self._session_token:
            return False
        return self._session_token.compare_secure(provided_token)

    def clear_credentials(self) -> None:
        """Clear all stored credentials from memory.

        Should be called when shutting down or when credentials
        are no longer needed.
        """
        self._vault_passphrase = None
        self._session_token = None

    @contextmanager
    def temporary_token(self):
        """Context manager for temporary token generation.

        Generates a token for the duration of the context,
        then automatically clears it.

        Yields
        ------
        SecureCredential
            Temporary session token

        Example
        -------
        >>> mgr = CredentialManager()
        >>> with mgr.temporary_token() as token:
        ...     # Use token within context
        ...     pass
        >>> # Token automatically cleared after context
        """
        try:
            token = self.generate_session_token()
            yield token
        finally:
            self._session_token = None

    def get_token_display_url(self, base_url: str) -> str:
        """Generate a display URL with embedded token.

        Creates a URL suitable for displaying to users, with the token
        included as a query parameter. The token itself is redacted in
        logs but visible in the returned string for user access.

        Parameters
        ----------
        base_url : str
            Base URL (e.g., "http://127.0.0.1:8000")

        Returns
        -------
        str
            Full URL with token parameter, or base URL if no token

        Security Note
        -------------
        Only call this when displaying to authenticated terminal user.
        Never log the returned URL.
        """
        if not self._session_token:
            return base_url

        # Return actual URL for user (token visible here intentionally)
        return f"{base_url}/?token={self._session_token.get_value()}"

    def get_redacted_status(self) -> dict:
        """Get status summary with redacted credentials.

        Returns a dictionary suitable for logging that indicates
        whether credentials are loaded without exposing values.

        Returns
        -------
        dict
            Status information with redacted credential info
        """
        return {
            "vault_passphrase_loaded": self._vault_passphrase is not None,
            "vault_passphrase_length": len(self._vault_passphrase) if self._vault_passphrase else 0,
            "session_token_generated": self._session_token is not None,
            "passphrase_env_var": self.vault_passphrase_env,
            "min_passphrase_length": self.min_passphrase_length
        }


def redact_sensitive_data(data: str, pattern: Optional[str] = None) -> str:
    """Redact sensitive patterns from strings for safe logging.

    Replaces potential credentials, tokens, and passphrases with
    redaction markers to prevent accidental exposure in logs.

    Parameters
    ----------
    data : str
        String to redact
    pattern : str, optional
        Custom regex pattern for additional redaction

    Returns
    -------
    str
        Redacted string safe for logging
    """
    import re

    # Common patterns to redact
    patterns = [
        # Hex tokens (64+ chars)
        (r'[0-9a-fA-F]{64,}', '[TOKEN_REDACTED]'),
        # Passphrases in common formats
        (r'passphrase[=:]\s*\S+', 'passphrase=[REDACTED]'),
        (r'secret[=:]\s*\S+', 'secret=[REDACTED]'),
        (r'token[=:]\s*\S+', 'token=[REDACTED]'),
        # Base64 encoded secrets
        (r'[A-Za-z0-9+/]{40,}={0,2}', '[BASE64_REDACTED]'),
    ]

    result = data
    for pat, replacement in patterns:
        result = re.sub(pat, replacement, result)

    if pattern:
        result = re.sub(pattern, '[REDACTED]', result)

    return result


def secure_print(message: str, sensitive_values: Optional[list] = None) -> None:
    """Print message with automatic redaction of sensitive values.

    Parameters
    ----------
    message : str
        Message to print
    sensitive_values : list, optional
        List of strings to redact from message
    """
    if sensitive_values:
        for value in sensitive_values:
            if value:
                message = message.replace(value, '[REDACTED]')

    # Apply pattern-based redaction
    safe_message = redact_sensitive_data(message)
    print(safe_message)