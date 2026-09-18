"""The SSRF guard is the security boundary for every partner-supplied URL."""

import asyncio

import pytest

from smart_sandbox.http import (
    REDACTED,
    is_allowed_destination,
    redact_body_text,
    redact_form,
    redact_headers,
    safe_request,
)
from tests.mock_ehr import BASE_URL, MockEhrState


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/fhir",  # https only
        "ftp://example.com/fhir",
        "https://127.0.0.1/fhir",  # loopback
        "https://localhost/fhir",
        "https://10.1.2.3/fhir",  # rfc1918
        "https://192.168.1.1/fhir",
        "https://169.254.169.254/latest/meta-data",  # cloud metadata
        "https://[::1]/fhir",  # ipv6 loopback
        "https://[fd00::1]/fhir",  # ipv6 ula
        "https://224.0.0.1/fhir",  # multicast
        "https://100.100.100.200/fhir",  # shared address space
    ],
)
async def test_private_and_plaintext_targets_are_blocked(url: str) -> None:
    response, transcripts = await safe_request("GET", url, allow_private=False)
    assert response is None
    assert transcripts[-1].error is not None


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data",  # cloud metadata
        "http://[fe80::1]/fhir",  # ipv6 link-local
        "http://100.100.100.200/latest/meta-data",  # shared address space
        "http://0.0.0.0/fhir",
        "http://224.0.0.1/fhir",  # multicast
        "http://[::ffff:169.254.169.254]/fhir",  # ipv4-mapped link-local
    ],
)
async def test_private_mode_still_blocks_link_local_and_reserved(url: str) -> None:
    response, transcripts = await safe_request("GET", url, allow_private=True)
    assert response is None
    assert "reserved" in (transcripts[-1].error or "")


async def test_private_mode_pins_connection_and_keeps_host_header() -> None:
    # GIVEN a plain-HTTP server on 127.0.0.1 that echoes the Host header
    seen: list[bytes] = []

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        seen.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        # WHEN requesting it by name (localhost resolves to ::1 first on many
        # systems, and nothing listens there)
        response, transcripts = await safe_request(
            "GET", f"http://localhost:{port}/fhir", allow_private=True
        )
    finally:
        server.close()
        await server.wait_closed()

    # THEN the vetted IPv4 address was dialled with the original Host header
    assert response is not None and response.body == b"ok", transcripts[-1].error
    assert f"Host: localhost:{port}".encode() in seen[0]


async def test_private_mode_allows_loopback() -> None:
    # Nothing listens on the discard port, so the request fails at connect
    # time — after passing the guard rather than being refused by it.
    response, transcripts = await safe_request(
        "GET", "http://127.0.0.1:9/fhir", allow_private=True
    )
    assert response is None
    error = transcripts[-1].error or ""
    assert "reserved" not in error and "non-public" not in error


@pytest.mark.parametrize(
    ("address", "strict", "private"),
    [
        ("93.184.216.34", True, True),  # public
        ("2606:2800:220:1:248:1893:25c8:1946", True, True),
        ("127.0.0.1", False, True),  # loopback
        ("::1", False, True),
        ("10.1.2.3", False, True),  # rfc1918 / ula
        ("192.168.1.1", False, True),
        ("fd00::1", False, True),
        ("169.254.169.254", False, False),  # link-local, never
        ("fe80::1", False, False),
        ("100.100.100.200", False, False),  # shared address space, never
        ("224.0.0.1", False, False),  # multicast, never
        ("0.0.0.0", False, False),
        ("::ffff:10.1.2.3", False, True),  # ipv4-mapped follows the ipv4 rule
        ("::ffff:169.254.169.254", False, False),
    ],
)
def test_destination_classification(address: str, strict: bool, private: bool) -> None:
    assert is_allowed_destination(address, allow_private=False) is strict
    assert is_allowed_destination(address, allow_private=True) is private


async def test_cross_origin_redirect_is_not_followed(mock_ehr: MockEhrState) -> None:
    # GIVEN an endpoint that bounces the request to another host
    response, transcripts = await safe_request(
        "GET",
        f"{BASE_URL}/redirect?to=https://attacker.example/collect",
        headers={"Authorization": "Bearer at-1"},
        allow_private=False,
    )

    # THEN the sandbox stops at the redirect instead of re-sending the
    # bearer token to the new origin
    assert response is None
    assert len(transcripts) == 1
    assert "Cross-origin" in (transcripts[0].error or "")


async def test_same_origin_redirect_is_followed(mock_ehr: MockEhrState) -> None:
    response, transcripts = await safe_request(
        "GET",
        f"{BASE_URL}/redirect?to=/echo-auth",
        headers={"Authorization": "Bearer at-1"},
        allow_private=False,
    )
    assert response is not None and response.status_code == 200
    assert len(transcripts) == 2
    assert response.json() == {"authorization": "Bearer at-1"}


async def test_unresolvable_host_is_blocked_cleanly() -> None:
    response, transcripts = await safe_request(
        "GET", "https://does-not-exist.invalid/fhir", allow_private=False
    )
    assert response is None
    assert "resolve" in (transcripts[-1].error or "").lower()


def test_authorization_and_cookie_headers_are_redacted() -> None:
    redacted = redact_headers(
        {"Authorization": "Bearer secret", "Cookie": "s=1", "Accept": "text/html"}
    )
    assert redacted["Authorization"] == REDACTED
    assert redacted["Cookie"] == REDACTED
    assert redacted["Accept"] == "text/html"


def test_sensitive_form_fields_are_redacted() -> None:
    encoded = redact_form(
        {
            "grant_type": "authorization_code",
            "code": "auth-code-value",
            "client_secret": "hunter2",
            "code_verifier": "pkce-verifier-value",
            "refresh_token": "rt-value",
        }
    )
    assert "auth-code-value" not in encoded
    assert "hunter2" not in encoded
    assert "pkce-verifier-value" not in encoded
    assert "rt-value" not in encoded
    assert "grant_type=authorization_code" in encoded


def test_token_response_bodies_are_redacted() -> None:
    body = (
        b'{"access_token": "at-1", "refresh_token": "rt-1", '
        b'"id_token": "jwt", "patient": "abc123"}'
    )
    text = redact_body_text(body)
    assert "at-1" not in text
    assert "rt-1" not in text
    assert '"patient": "abc123"' in text
