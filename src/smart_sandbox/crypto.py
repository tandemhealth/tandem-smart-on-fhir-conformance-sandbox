import hashlib
import hmac
import logging
import secrets

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


def new_url_token() -> str:
    """Unguessable capability token, URL-safe (256 bits of entropy)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def token_matches_hash(token: str, token_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), token_hash)


class SecretBox:
    """Symmetric encryption for partner client secrets and OAuth tokens.

    Without a configured key an ephemeral one is generated, so stored secrets
    do not survive a restart.
    """

    def __init__(self, key: str | None) -> None:
        if key is None:
            logger.warning(
                "SANDBOX_SECRETS_KEY is not set; generating an ephemeral key. "
                "Stored secrets will not be readable after a restart."
            )
            key = Fernet.generate_key().decode()
        self._fernet = Fernet(key)

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()
