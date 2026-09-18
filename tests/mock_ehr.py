"""In-process mock EHR: SMART configuration, OAuth authorize/token, and a
minimal FHIR R4 API — with switchable failure modes for conformance tests."""

import base64
import hashlib
import json
import secrets
import urllib.parse
from dataclasses import dataclass, field

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

BASE_URL = "https://mock-ehr.example"
ISS = f"{BASE_URL}/fhir"
CLIENT_ID = "sandbox-client-id"
CLIENT_SECRET = "sandbox-client-secret"
PATIENT_ID = "abc123"
ENCOUNTER_ID = "enc-123"
PRACTITIONER = f"{ISS}/Practitioner/doc-001"
LAUNCH_TOKEN = "launch-token-1"

# Form data registering this mock EHR as a sandbox client.
REGISTRATION_FORM = {
    "name": "Mock EHR AB",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "token_auth_method": "client_secret_basic",
    "expected_iss": ISS,
}


@dataclass
class MockEhrConfig:
    # Failure modes, each mapping to a conformance check the sandbox reports.
    omit_pkce_support: bool = False
    # Advertise scopes the way many real servers do: wildcards in SMART v2
    # syntax rather than the literal v1 scopes an app requests.
    advertise_wildcard_scopes: bool = False
    omit_encounter_context: bool = False
    encounter_wrong_subject: bool = False
    writeback_omit_location: bool = False
    writeback_status: int = 201
    omit_refresh_token: bool = False


@dataclass
class MockEhrState:
    codes: dict[str, dict[str, str]] = field(default_factory=dict)
    valid_access_tokens: set[str] = field(default_factory=set)
    refresh_count: int = 0
    authorize_requests: list[dict[str, str]] = field(default_factory=list)
    token_requests: list[dict[str, str]] = field(default_factory=list)
    created_resources: list[dict[str, object]] = field(default_factory=list)


def _unsigned_jwt(payload: dict[str, object]) -> str:
    def b64(part: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64(payload)}.signature"


def create_mock_ehr(
    config: MockEhrConfig | None = None,
) -> tuple[FastAPI, MockEhrState]:
    config = config or MockEhrConfig()
    state = MockEhrState()
    app = FastAPI()

    @app.get("/fhir/.well-known/smart-configuration")
    async def smart_configuration() -> dict[str, object]:  # pyright: ignore[reportUnusedFunction]
        doc: dict[str, object] = {
            "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
            "token_endpoint": f"{BASE_URL}/oauth/token",
            "scopes_supported": (
                ["launch", "openid", "fhirUser", "offline_access", "patient/*.cruds"]
                if config.advertise_wildcard_scopes
                else [
                    "launch",
                    "openid",
                    "fhirUser",
                    "offline_access",
                    "patient/Patient.read",
                    "patient/Encounter.read",
                    "patient/DocumentReference.write",
                    "patient/Condition.write",
                ]
            ),
            "response_types_supported": ["code"],
            "capabilities": [
                "launch-ehr",
                "client-confidential-symmetric",
                "context-ehr-patient",
                "context-ehr-encounter",
                "permission-patient",
            ],
            "code_challenge_methods_supported": []
            if config.omit_pkce_support
            else ["S256"],
        }
        return doc

    @app.get("/oauth/authorize")
    async def authorize(request: Request) -> Response:  # pyright: ignore[reportUnusedFunction]
        params = dict(request.query_params)
        state.authorize_requests.append(params)
        assert params["response_type"] == "code"
        assert params["client_id"] == CLIENT_ID
        assert params["aud"] == ISS
        assert params["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(12)
        state.codes[code] = {
            "code_challenge": params["code_challenge"],
            "redirect_uri": params["redirect_uri"],
        }
        redirect = (
            params["redirect_uri"]
            + "?"
            + urllib.parse.urlencode({"code": code, "state": params["state"]})
        )
        return RedirectResponse(url=redirect, status_code=302)

    def _client_authenticated(authorization: str | None, form: dict[str, str]) -> bool:
        if authorization is not None and authorization.startswith("Basic "):
            expected = base64.b64encode(
                f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
            ).decode()
            return authorization.removeprefix("Basic ") == expected
        return form.get("client_secret") == CLIENT_SECRET

    def _issue_tokens() -> dict[str, object]:
        access_token = f"at-{secrets.token_urlsafe(8)}"
        state.valid_access_tokens.add(access_token)
        tokens: dict[str, object] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "launch openid fhirUser offline_access "
            "patient/Patient.read patient/Encounter.read "
            "patient/DocumentReference.write patient/Condition.write",
            "id_token": _unsigned_jwt({"sub": "doc-001", "fhirUser": PRACTITIONER}),
        }
        if not config.omit_refresh_token:
            tokens["refresh_token"] = "rt-1"
        return tokens

    @app.post("/oauth/token")
    async def token(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> Response:
        form = dict(urllib.parse.parse_qsl((await request.body()).decode()))
        state.token_requests.append(form)
        if not _client_authenticated(authorization, form):
            return JSONResponse({"error": "invalid_client"}, status_code=401)

        if form.get("grant_type") == "refresh_token":
            if form.get("refresh_token") != "rt-1":
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            state.refresh_count += 1
            return JSONResponse(_issue_tokens())

        assert form.get("grant_type") == "authorization_code"
        issued = state.codes.pop(form.get("code", ""), None)
        if issued is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        # PKCE: the S256 hash of the presented verifier must match.
        digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if challenge != issued["code_challenge"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if form.get("redirect_uri") != issued["redirect_uri"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        tokens = _issue_tokens()
        tokens["patient"] = PATIENT_ID
        if not config.omit_encounter_context:
            tokens["encounter"] = ENCOUNTER_ID
        return JSONResponse(tokens)

    def _bearer_ok(authorization: str | None) -> bool:
        return (
            authorization is not None
            and authorization.removeprefix("Bearer ") in state.valid_access_tokens
        )

    @app.get("/fhir/Patient/{patient_id}")
    async def patient(  # pyright: ignore[reportUnusedFunction]
        patient_id: str, authorization: str | None = Header(default=None)
    ) -> Response:
        if not _bearer_ok(authorization):
            return JSONResponse({"resourceType": "OperationOutcome"}, status_code=401)
        return JSONResponse(
            {
                "resourceType": "Patient",
                "id": patient_id,
                "name": [
                    {
                        "text": "John Michael Doe",
                        "family": "Doe",
                        "given": ["John", "Michael"],
                    }
                ],
                "birthDate": "1988-07-01",
                "gender": "male",
            }
        )

    @app.get("/fhir/Encounter/{encounter_id}")
    async def encounter(  # pyright: ignore[reportUnusedFunction]
        encounter_id: str, authorization: str | None = Header(default=None)
    ) -> Response:
        if not _bearer_ok(authorization):
            return JSONResponse({"resourceType": "OperationOutcome"}, status_code=401)
        subject = (
            "Patient/someone-else"
            if config.encounter_wrong_subject
            else f"Patient/{PATIENT_ID}"
        )
        return JSONResponse(
            {
                "resourceType": "Encounter",
                "id": encounter_id,
                "status": "in-progress",
                "class": {
                    "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                    "code": "AMB",
                    "display": "ambulatory",
                },
                "subject": {"reference": subject},
                "participant": [{"individual": {"reference": "Practitioner/doc-001"}}],
                "period": {"start": "2026-08-13T10:00:00Z"},
            }
        )

    async def _create(request: Request, resource_type: str) -> Response:
        authorization = request.headers.get("authorization")
        if not _bearer_ok(authorization):
            return JSONResponse(
                {
                    "resourceType": "OperationOutcome",
                    "issue": [{"severity": "error", "code": "expired"}],
                },
                status_code=401,
            )
        resource = json.loads(await request.body())
        assert resource["resourceType"] == resource_type
        state.created_resources.append(resource)
        resource_id = f"{resource_type.lower()}-{len(state.created_resources)}"
        headers = (
            {}
            if config.writeback_omit_location
            else {"Location": f"{ISS}/{resource_type}/{resource_id}"}
        )
        return JSONResponse(
            {**resource, "id": resource_id},
            status_code=config.writeback_status,
            headers=headers,
        )

    @app.post("/fhir/DocumentReference")
    async def create_document_reference(request: Request) -> Response:  # pyright: ignore[reportUnusedFunction]
        return await _create(request, "DocumentReference")

    @app.post("/fhir/Condition")
    async def create_condition(request: Request) -> Response:  # pyright: ignore[reportUnusedFunction]
        return await _create(request, "Condition")

    @app.get("/redirect")
    async def redirect(to: str) -> Response:  # pyright: ignore[reportUnusedFunction]
        return RedirectResponse(url=to, status_code=307)

    @app.get("/echo-auth")
    async def echo_auth(  # pyright: ignore[reportUnusedFunction]
        authorization: str | None = Header(default=None),
    ) -> dict[str, str | None]:
        return {"authorization": authorization}

    return app, state
