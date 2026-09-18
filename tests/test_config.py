import pytest
from pydantic import ValidationError

from smart_sandbox.config import Settings


def _settings(**overrides: object) -> Settings:
    # _env_file=None keeps a developer's local .env out of the test.
    return Settings(_env_file=None, **overrides)  # pyright: ignore[reportCallIssue]


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8090",
        "http://127.0.0.1:8090",
        "http://[::1]:8090",
        "http://sandbox.localhost:8090",
    ],
)
def test_private_network_allowed_on_loopback_urls(base_url: str) -> None:
    settings = _settings(
        SANDBOX_PUBLIC_BASE_URL=base_url, SANDBOX_ALLOW_PRIVATE_NETWORK=True
    )
    assert settings.SANDBOX_ALLOW_PRIVATE_NETWORK is True


@pytest.mark.parametrize(
    "base_url",
    [
        "https://abc123.ngrok.app",
        "https://sandbox.example.com",
        "http://192.168.1.20:8090",
        "http://10.0.0.5:8090",
    ],
)
def test_private_network_refused_behind_tunnel_or_lan_url(base_url: str) -> None:
    # Open registration plus private-network access must never be reachable
    # from outside the machine: the combination is refused at startup.
    with pytest.raises(ValidationError, match="SANDBOX_ALLOW_PRIVATE_NETWORK"):
        _settings(SANDBOX_PUBLIC_BASE_URL=base_url, SANDBOX_ALLOW_PRIVATE_NETWORK=True)


def test_tunnel_url_is_fine_without_private_network() -> None:
    settings = _settings(
        SANDBOX_PUBLIC_BASE_URL="https://abc123.ngrok.app",
        SANDBOX_ALLOW_PRIVATE_NETWORK=False,
    )
    assert settings.SANDBOX_PUBLIC_BASE_URL == "https://abc123.ngrok.app"
