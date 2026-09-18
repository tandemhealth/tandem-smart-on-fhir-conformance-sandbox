"""SSRF-guarded HTTP client for calling partner-supplied URLs.

Every URL this service fetches (the FHIR base, the discovered OAuth endpoints)
comes from a registration or launch request that anyone able to reach the
sandbox can make, so the sandbox must not become a proxy into the network it
runs on. By default requests are only allowed to public addresses:

- https:// only (http allowed only with SANDBOX_ALLOW_PRIVATE_NETWORK)
- the hostname is resolved up front and every resolved address must be a
  global (public) IP; the connection is then pinned to the vetted IP while TLS
  still verifies against the original hostname (defeats DNS rebinding)
- with SANDBOX_ALLOW_PRIVATE_NETWORK (running against a dev EHR on the same
  machine or LAN) loopback and private-range addresses are additionally
  allowed, but link-local (cloud metadata), multicast, unspecified and other
  reserved ranges stay blocked; the connection is pinned in this mode too
- redirects are followed manually (max 3) with the same vetting per hop and
  only within the same origin, so credentials and bodies are never re-sent to
  another host
- response size and total time are capped

Each exchange is recorded as a redacted HttpTranscript for the run report:
credentials, tokens, and authorization codes never appear in stored
transcripts or logs.
"""

import asyncio
import ipaddress
import json
import socket
import time
import urllib.parse
from dataclasses import dataclass
from typing import cast

import httpx

from smart_sandbox.models import HttpTranscript

MAX_RESPONSE_BYTES = 2_000_000
STORED_BODY_MAX_CHARS = 20_000
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = httpx.Timeout(15.0, connect=5.0)

REDACTED = "<redacted>"
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}
_SENSITIVE_FORM_FIELDS = {"client_secret", "code", "code_verifier", "refresh_token"}
_SENSITIVE_JSON_FIELDS = {"access_token", "refresh_token", "id_token"}

# Test hook: when set, requests are routed through this transport (an
# in-process mock EHR) and DNS/IP vetting is skipped since no socket is opened.
TEST_TRANSPORT: httpx.AsyncBaseTransport | None = None


class BlockedRequestError(Exception):
    """Request refused by the SSRF guard; the message is partner-safe."""


@dataclass
class SafeResponse:
    status_code: int
    headers: httpx.Headers
    body: bytes

    def json(self) -> dict[str, object] | None:
        """Parse the body as a JSON object; None for invalid or non-object JSON."""
        try:
            parsed: object = json.loads(self.body)
        except (ValueError, UnicodeDecodeError):
            return None
        if isinstance(parsed, dict):
            return cast("dict[str, object]", parsed)
        return None


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k: (REDACTED if k.lower() in _SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def redact_form(data: dict[str, str]) -> str:
    return urllib.parse.urlencode(
        {k: (REDACTED if k in _SENSITIVE_FORM_FIELDS else v) for k, v in data.items()}
    )


def _redact_json_value(value: object) -> object:
    if isinstance(value, dict):
        items = cast("dict[str, object]", value)
        return {
            k: (REDACTED if k in _SENSITIVE_JSON_FIELDS else _redact_json_value(v))
            for k, v in items.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(v) for v in cast("list[object]", value)]
    return value


def redact_body_text(body: bytes) -> str:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(body)} bytes of non-text data>"
    try:
        parsed: object = json.loads(text)
    except ValueError:
        return text[:STORED_BODY_MAX_CHARS]
    redacted = json.dumps(_redact_json_value(parsed), indent=2)
    return redacted[:STORED_BODY_MAX_CHARS]


# Shared address space (RFC 6598); not flagged by ipaddress as private but
# never a legitimate EHR endpoint, and used for cloud metadata by some
# providers.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


def is_allowed_destination(address: str, *, allow_private: bool) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # ::1 is also is_reserved, so loopback is decided before the block list.
    if ip.is_loopback:
        return allow_private
    # Never a legitimate endpoint in any mode. Checked before is_global
    # because ipaddress reports e.g. multicast as global.
    if (
        ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or (isinstance(ip, ipaddress.IPv4Address) and ip in _SHARED_ADDRESS_SPACE)
    ):
        return False
    if ip.is_global:
        return True
    return allow_private and ip.is_private


async def _vet_url(url: httpx.URL, *, allow_private: bool) -> str | None:
    """Validate scheme and destination; return the vetted IP to connect to.

    Returns None only for the in-process test transport, where no socket is
    opened. Raises BlockedRequestError when the URL must not be fetched.
    """
    if url.scheme != "https" and not (allow_private and url.scheme == "http"):
        raise BlockedRequestError(
            f"Only https:// URLs are allowed (got {url.scheme}://)."
        )
    if TEST_TRANSPORT is not None:
        return None

    host = url.host
    port = url.port or (443 if url.scheme == "https" else 80)
    try:
        # Host may already be an IP literal; getaddrinfo handles both.
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise BlockedRequestError(f"Could not resolve host {host!r}.") from exc

    addresses = [str(info[4][0]) for info in infos]
    if not addresses:
        raise BlockedRequestError(f"Could not resolve host {host!r}.")
    for address in addresses:
        if not is_allowed_destination(address, allow_private=allow_private):
            if allow_private:
                raise BlockedRequestError(
                    f"Host {host!r} resolves to a link-local or reserved "
                    "address; the sandbox never calls those."
                )
            raise BlockedRequestError(
                f"Host {host!r} resolves to a non-public address; the sandbox "
                "only calls publicly reachable endpoints."
            )
    # Prefer IPv4 for the pin: dev EHRs are commonly bound to 127.0.0.1 only,
    # while `localhost` resolves to ::1 first on many systems.
    return next(
        (
            a
            for a in addresses
            if isinstance(ipaddress.ip_address(a), ipaddress.IPv4Address)
        ),
        addresses[0],
    )


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    return (url.scheme, url.host, url.port)


def _build_request(
    client: httpx.AsyncClient,
    method: str,
    url: httpx.URL,
    vetted_ip: str | None,
    *,
    headers: dict[str, str],
    form: dict[str, str] | None,
    json_body: dict[str, object] | None,
) -> httpx.Request:
    if vetted_ip is None:
        return client.build_request(
            method, url, headers=headers, data=form, json=json_body
        )
    # Pin the connection to the vetted IP: swap the URL host for the IP, keep
    # the original hostname for the Host header and for TLS SNI/verification
    # (httpcore uses the sni_hostname extension as server_hostname, so the
    # certificate is still checked against the real hostname).
    host_header = url.host if url.port is None else f"{url.host}:{url.port}"
    pinned = url.copy_with(host=vetted_ip)
    return client.build_request(
        method,
        pinned,
        headers={**headers, "Host": host_header},
        data=form,
        json=json_body,
        extensions={"sni_hostname": url.host},
    )


async def safe_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    allow_private: bool,
) -> tuple[SafeResponse | None, list[HttpTranscript]]:
    """Perform a vetted HTTP request, following up to MAX_REDIRECTS manually.

    Returns the final response (None if the request could not complete) and
    the redacted transcripts of every hop.
    """
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "tandem-smart-sandbox/1.0")
    transcripts: list[HttpTranscript] = []

    request_body_text: str | None = None
    if form is not None:
        request_body_text = redact_form(form)
    elif json_body is not None:
        request_body_text = json.dumps(json_body, indent=2)[:STORED_BODY_MAX_CHARS]

    current = httpx.URL(url)
    current_method = method
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT, transport=TEST_TRANSPORT
    ) as client:
        for hop in range(MAX_REDIRECTS + 1):
            transcript = HttpTranscript(
                method=current_method,
                url=str(current),
                request_headers=redact_headers(headers),
                request_body=request_body_text if current_method != "GET" else None,
            )
            transcripts.append(transcript)
            started = time.monotonic()
            try:
                vetted_ip = await _vet_url(current, allow_private=allow_private)
                request = _build_request(
                    client,
                    current_method,
                    current,
                    vetted_ip,
                    headers=headers,
                    form=form if current_method != "GET" else None,
                    json_body=json_body if current_method != "GET" else None,
                )
                response = await client.send(request, stream=True)
                try:
                    body = b""
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise BlockedRequestError(
                                "Response exceeded the sandbox size limit "
                                f"({MAX_RESPONSE_BYTES} bytes)."
                            )
                finally:
                    await response.aclose()
            except BlockedRequestError as exc:
                transcript.error = str(exc)
                return None, transcripts
            except httpx.HTTPError as exc:
                transcript.error = f"{type(exc).__name__}: {exc}"
                return None, transcripts
            finally:
                transcript.elapsed_ms = int((time.monotonic() - started) * 1000)

            transcript.status_code = response.status_code
            transcript.response_headers = redact_headers(dict(response.headers))
            transcript.response_body = redact_body_text(body)

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if location is None or hop == MAX_REDIRECTS:
                    transcript.error = "Redirect could not be followed."
                    return None, transcripts
                target = current.join(location)
                # Never re-send credentials or bodies to another origin.
                if _origin(target) != _origin(current):
                    transcript.error = (
                        "Cross-origin redirect refused: the sandbox only follows "
                        "redirects within the same scheme, host and port."
                    )
                    return None, transcripts
                current = target
                if response.status_code == 303:
                    current_method = "GET"
                    form = None
                    json_body = None
                    request_body_text = None
                continue

            return (
                SafeResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    body=body,
                ),
                transcripts,
            )

    transcripts[-1].error = "Too many redirects."
    return None, transcripts
