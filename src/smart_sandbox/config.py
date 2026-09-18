import ipaddress
import urllib.parse

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _is_loopback_url(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Public base URL of this sandbox as reached by the browser and by your
    # EHR's redirect. Used to build the OAuth redirect URI and the launch URLs
    # shown in the UI. Point it at a tunnel (ngrok, cloudflared, ...) if your
    # authorization server refuses http://localhost redirect URIs.
    SANDBOX_PUBLIC_BASE_URL: str = Field(default="http://localhost:8090")

    # SQLite database file holding registrations and runs.
    SANDBOX_DB_PATH: str = Field(default=".run/smart-sandbox.sqlite3")

    # Fernet key encrypting client secrets and OAuth tokens at rest. When
    # unset an ephemeral key is generated at boot, so registrations do not
    # survive a restart. Generate one with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    SANDBOX_SECRETS_KEY: str | None = Field(default=None)

    # Allow http:// plus loopback and private-range (RFC 1918 / ULA) EHR
    # endpoints, which the SSRF guard otherwise rejects. Link-local (cloud
    # metadata), multicast and other reserved ranges stay blocked. Enable this
    # when the EHR under test runs on your own machine or LAN, and keep the
    # sandbox bound to 127.0.0.1 while it is on: registration is open to
    # anyone who can reach the port.
    SANDBOX_ALLOW_PRIVATE_NETWORK: bool = Field(default=False)

    # Registrations expire after this many days and are purged lazily.
    SANDBOX_REGISTRATION_TTL_DAYS: int = Field(default=90)

    # Cap on concurrently active registrations.
    SANDBOX_MAX_PARTNERS: int = Field(default=500)

    @model_validator(mode="after")
    def _private_network_requires_local_url(self) -> "Settings":
        # Registration is open to anyone who can reach the sandbox. Behind a
        # tunnel that is the whole Internet, and with private networking on
        # they could point discovery at services on this machine or its LAN.
        if self.SANDBOX_ALLOW_PRIVATE_NETWORK and not _is_loopback_url(
            self.SANDBOX_PUBLIC_BASE_URL
        ):
            raise ValueError(
                "SANDBOX_ALLOW_PRIVATE_NETWORK=true is only allowed while "
                "SANDBOX_PUBLIC_BASE_URL points at localhost. When exposing the "
                f"sandbox at {self.SANDBOX_PUBLIC_BASE_URL} (e.g. through a "
                "tunnel), set SANDBOX_ALLOW_PRIVATE_NETWORK=false so remote "
                "callers cannot direct requests into your machine or network."
            )
        return self


settings = Settings()
