"""SMART App Launch client operations: discovery, authorization, token
exchange, and refresh — each returning a conformance-checked Step."""

import base64
import hashlib
import json
import secrets
import urllib.parse

from smart_sandbox.checks import Checker
from smart_sandbox.http import safe_request
from smart_sandbox.jsonval import as_object, as_str_list
from smart_sandbox.models import (
    CheckSeverity,
    LaunchMode,
    Partner,
    Step,
    TokenAuthMethod,
    new_step,
)

SCOPES = [
    "launch",
    "openid",
    "fhirUser",
    "offline_access",
    "patient/Patient.read",
    "patient/Encounter.read",
    "patient/DocumentReference.write",
    "patient/Condition.write",
]

# SMART v1 access verbs expressed as v2 permission letters (c/r/u/d/s).
_V1_PERMISSIONS = {"read": set("rs"), "write": set("cud"), "*": set("cruds")}


def _parse_resource_scope(scope: str) -> tuple[str, str, set[str]] | None:
    """Split `context/Resource.perms` into (context, resource, permission
    letters); None for non-resource scopes such as openid or launch."""
    context, sep, rest = scope.partition("/")
    if not sep or context not in ("patient", "user", "system"):
        return None
    # v2 scopes may carry a query (`patient/Observation.rs?category=...`);
    # that narrows the grant, so it never counts as covering our request.
    if "?" in rest:
        return None
    resource, sep, perms = rest.partition(".")
    if not sep or not resource or not perms:
        return None
    if perms in _V1_PERMISSIONS:
        return context, resource, set(_V1_PERMISSIONS[perms])
    if set(perms) <= set("cruds"):
        return context, resource, set(perms)
    return None


def scope_is_covered(requested: str, advertised: set[str]) -> bool:
    """Whether an advertised scope grants at least what `requested` asks for.

    Servers commonly advertise wildcards (`patient/*.*`) or SMART v2 syntax
    (`patient/*.rs`) rather than the literal v1 scope an app requests.
    """
    if requested in advertised:
        return True
    wanted = _parse_resource_scope(requested)
    if wanted is None:
        return False
    context, resource, perms = wanted
    for candidate in advertised:
        parsed = _parse_resource_scope(candidate)
        if parsed is None:
            continue
        c_context, c_resource, c_perms = parsed
        if c_context == context and c_resource in (resource, "*") and perms <= c_perms:
            return True
    return False


_EXPECTED_CAPABILITIES = {
    "launch-ehr",
    "context-ehr-patient",
    "context-ehr-encounter",
}


def _is_https(url: object) -> bool:
    return isinstance(url, str) and url.startswith("https://")


def _endpoint_ok(url: object, *, allow_private: bool) -> bool:
    if allow_private:
        return isinstance(url, str) and url.startswith(("https://", "http://"))
    return _is_https(url)


async def discover(
    iss: str, *, launch_mode: LaunchMode, allow_private: bool
) -> tuple[dict[str, object] | None, Step]:
    """Fetch and validate {iss}/.well-known/smart-configuration (guide §3.1)."""
    step = new_step("discovery", "SMART configuration discovery", "§3.1")
    checker = Checker(step)

    url = iss.rstrip("/") + "/.well-known/smart-configuration"
    response, transcripts = await safe_request(
        "GET",
        url,
        headers={"Accept": "application/json"},
        allow_private=allow_private,
    )
    step.http.extend(transcripts)

    if not checker.check(
        "discovery.reachable",
        "The SMART configuration document is reachable",
        "§3.1",
        response is not None,
        detail=transcripts[-1].error or "",
    ):
        return None, step
    assert response is not None

    if not checker.check(
        "discovery.status",
        "GET /.well-known/smart-configuration returns 200",
        "§3.1",
        response.status_code == 200,
        detail=f"Got HTTP {response.status_code}.",
    ):
        return None, step

    config = response.json()
    if not checker.check(
        "discovery.json",
        "The configuration document is valid JSON",
        "§3.1",
        config is not None,
    ):
        return None, step
    assert config is not None

    ok = checker.check(
        "discovery.authorization_endpoint",
        "authorization_endpoint is present and served over TLS",
        "§3.1",
        _endpoint_ok(config.get("authorization_endpoint"), allow_private=allow_private),
        detail=f"authorization_endpoint: {config.get('authorization_endpoint')!r}",
    )
    ok = (
        checker.check(
            "discovery.token_endpoint",
            "token_endpoint is present and served over TLS",
            "§3.1",
            _endpoint_ok(config.get("token_endpoint"), allow_private=allow_private),
            detail=f"token_endpoint: {config.get('token_endpoint')!r}",
        )
        and ok
    )
    ok = (
        checker.check(
            "discovery.pkce",
            "code_challenge_methods_supported includes S256 (PKCE is required)",
            "§3.1, §7",
            "S256" in as_str_list(config.get("code_challenge_methods_supported")),
        )
        and ok
    )

    response_types = as_str_list(config.get("response_types_supported"))
    checker.check(
        "discovery.response_types",
        "response_types_supported includes 'code'",
        "§3.1",
        "code" in (response_types or ["code"]),
        severity=CheckSeverity.WARN,
    )
    capabilities = set(as_str_list(config.get("capabilities")))
    if launch_mode == LaunchMode.EHR:
        missing = _EXPECTED_CAPABILITIES - capabilities
        checker.check(
            "discovery.capabilities",
            "capabilities advertise EHR launch with patient and encounter context",
            "§3.1",
            not missing,
            severity=CheckSeverity.WARN,
            detail=f"Missing: {sorted(missing)}" if missing else "",
        )
    scopes_supported = set(as_str_list(config.get("scopes_supported")))
    if scopes_supported:
        missing_scopes = [
            s for s in SCOPES if not scope_is_covered(s, scopes_supported)
        ]
        checker.check(
            "discovery.scopes",
            "scopes_supported covers every scope Tandem requests",
            "§3.4",
            not missing_scopes,
            severity=CheckSeverity.WARN,
            detail=(
                f"Not covered: {missing_scopes} (wildcards such as patient/*.* "
                "and SMART v2 syntax such as patient/*.rs are accepted)."
                if missing_scopes
                else "Advertised literally, by wildcard, or in SMART v2 syntax."
            ),
        )

    return (config if ok else None), step


def build_authorization_redirect(
    *,
    partner: Partner,
    smart_config: dict[str, object],
    iss: str,
    launch: str | None,
    redirect_uri: str,
) -> tuple[str, str, str, Step]:
    """Build the §3.2 authorization request. Returns (url, state, verifier, step)."""
    step = new_step("authorize", "Authorization request", "§3.2")
    checker = Checker(step)

    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )

    scopes = SCOPES if launch is not None else [s for s in SCOPES if s != "launch"]
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": partner.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "aud": iss,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if launch is not None:
        params["launch"] = launch

    authorization_endpoint = str(smart_config["authorization_endpoint"])
    url = (
        authorization_endpoint
        + ("&" if "?" in authorization_endpoint else "?")
        + urllib.parse.urlencode(params)
    )

    checker.info(
        "authorize.request",
        "Redirecting the browser to the authorization endpoint",
        "§3.2",
        detail=json.dumps(
            {k: v for k, v in params.items() if k != "code_challenge"}, indent=2
        ),
    )
    return url, state, verifier, step


def _token_request(
    partner: Partner,
    client_secret: str | None,
    form: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Apply the partner's registered client authentication method (§3.3)."""
    headers = {"Accept": "application/json"}
    if partner.token_auth_method == TokenAuthMethod.CLIENT_SECRET_BASIC:
        credentials = base64.b64encode(
            f"{partner.client_id}:{client_secret or ''}".encode()
        ).decode()
        headers["Authorization"] = f"Basic {credentials}"
    elif partner.token_auth_method == TokenAuthMethod.CLIENT_SECRET_POST:
        form["client_secret"] = client_secret or ""
    return headers, form


def _decode_jwt_payload(token: str) -> dict[str, object] | None:
    try:
        payload_part = token.split(".")[1]
        padded = payload_part + "=" * (-len(payload_part) % 4)
        payload: object = json.loads(base64.urlsafe_b64decode(padded))
    except (IndexError, ValueError):
        return None
    return as_object(payload)


def _check_token_response(
    checker: Checker,
    token_data: dict[str, object],
    *,
    launch_mode: LaunchMode,
) -> None:
    checker.check(
        "token.access_token",
        "The token response contains an access_token",
        "§3.3",
        bool(token_data.get("access_token")),
    )
    token_type = token_data.get("token_type")
    checker.check(
        "token.token_type",
        "token_type is Bearer",
        "§3.3",
        isinstance(token_type, str) and token_type.lower() == "bearer",
        detail=f"token_type: {token_type!r}",
    )
    checker.check(
        "token.expires_in",
        "expires_in is present and numeric",
        "§3.3",
        isinstance(token_data.get("expires_in"), int | float),
        severity=CheckSeverity.WARN,
    )
    checker.check(
        "token.patient",
        "The launch context includes the patient id",
        "§3.3",
        bool(token_data.get("patient")),
    )
    checker.check(
        "token.encounter",
        "The launch context includes the encounter id",
        "§3.3",
        bool(token_data.get("encounter")),
        severity=(
            CheckSeverity.FAIL if launch_mode == LaunchMode.EHR else CheckSeverity.WARN
        ),
        detail=(
            "Required for EHR launch from an open encounter."
            if launch_mode == LaunchMode.EHR
            else "Standalone launch: encounter context is expected after selection."
        ),
    )
    checker.check(
        "token.refresh_token",
        "A refresh_token is issued (offline_access)",
        "§3.5",
        bool(token_data.get("refresh_token")),
        severity=CheckSeverity.WARN,
        detail=(
            "Without a refresh token Tandem cannot complete the write-back "
            "if the access token expires mid-encounter."
        ),
    )
    checker.check(
        "token.id_token",
        "An id_token is issued (openid scope)",
        "§3.3",
        bool(token_data.get("id_token")),
        severity=CheckSeverity.WARN,
    )


def extract_fhir_user(token_data: dict[str, object]) -> str | None:
    fhir_user = token_data.get("fhirUser")
    if isinstance(fhir_user, str) and fhir_user:
        return fhir_user
    id_token = token_data.get("id_token")
    if isinstance(id_token, str):
        payload = _decode_jwt_payload(id_token)
        if payload is not None:
            claim = payload.get("fhirUser")
            if isinstance(claim, str) and claim:
                return claim
    return None


async def exchange_code(
    *,
    partner: Partner,
    client_secret: str | None,
    token_endpoint: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    launch_mode: LaunchMode,
    allow_private: bool,
) -> tuple[dict[str, object] | None, Step]:
    """Exchange the authorization code (guide §3.3) and validate the context."""
    step = new_step("token", "Token exchange & launch context", "§3.3")
    checker = Checker(step)

    headers, form = _token_request(
        partner,
        client_secret,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": partner.client_id,
            "code_verifier": code_verifier,
        },
    )
    response, transcripts = await safe_request(
        "POST",
        token_endpoint,
        headers=headers,
        form=form,
        allow_private=allow_private,
    )
    step.http.extend(transcripts)

    if not checker.check(
        "token.reachable",
        "The token endpoint responded",
        "§3.3",
        response is not None,
        detail=transcripts[-1].error or "",
    ):
        return None, step
    assert response is not None

    if not checker.check(
        "token.status",
        "The token exchange returns 200",
        "§3.3",
        response.status_code == 200,
        detail=f"Got HTTP {response.status_code}.",
    ):
        return None, step

    token_data = response.json()
    if not checker.check(
        "token.json",
        "The token response is valid JSON",
        "§3.3",
        token_data is not None,
    ):
        return None, step
    assert token_data is not None

    _check_token_response(checker, token_data, launch_mode=launch_mode)

    fhir_user = extract_fhir_user(token_data)
    checker.check(
        "token.fhir_user",
        "fhirUser identifies the launching user",
        "§3.3",
        fhir_user is not None,
        severity=CheckSeverity.WARN,
        detail=(
            f"fhirUser: {fhir_user}"
            if fhir_user
            else "Not found in the token response or the id_token claims. "
            "Tandem uses it to record note authorship."
        ),
    )
    if token_data.get("id_token"):
        checker.info(
            "token.id_token_signature",
            "id_token signature is not verified by the sandbox",
            "§3.3",
            "Production Tandem validates the id_token via OIDC; the sandbox "
            "only decodes its claims.",
        )

    if not token_data.get("access_token") or not token_data.get("patient"):
        return None, step
    return token_data, step


async def refresh_tokens(
    *,
    partner: Partner,
    client_secret: str | None,
    token_endpoint: str,
    refresh_token: str,
    allow_private: bool,
) -> tuple[dict[str, object] | None, Step]:
    """Use the refresh token to obtain a new access token (guide §3.5)."""
    step = new_step("refresh", "Refresh token exchange", "§3.5")
    checker = Checker(step)

    headers, form = _token_request(
        partner,
        client_secret,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": partner.client_id,
        },
    )
    response, transcripts = await safe_request(
        "POST",
        token_endpoint,
        headers=headers,
        form=form,
        allow_private=allow_private,
    )
    step.http.extend(transcripts)

    if not checker.check(
        "refresh.reachable",
        "The token endpoint responded",
        "§3.5",
        response is not None,
        detail=transcripts[-1].error or "",
    ):
        return None, step
    assert response is not None

    if not checker.check(
        "refresh.status",
        "The refresh exchange returns 200",
        "§3.5",
        response.status_code == 200,
        detail=f"Got HTTP {response.status_code}.",
    ):
        return None, step

    token_data = response.json()
    if not checker.check(
        "refresh.access_token",
        "The refresh response contains a new access_token",
        "§3.5",
        token_data is not None and bool(token_data.get("access_token")),
    ):
        return None, step
    assert token_data is not None
    return token_data, step
