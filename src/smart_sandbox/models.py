"""Domain models for partner registrations and conformance runs.

Everything the sandbox stores is partner-supplied test configuration and
synthetic test data; the sandbox must never be connected to a system holding
real patient data.
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class CheckSeverity(StrEnum):
    # A failed FAIL check means the partner implementation violates the
    # integration contract; WARN is a deviation Tandem can tolerate but that
    # should be fixed; INFO is informational either way.
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"


class CheckResult(BaseModel):
    check_id: str
    description: str
    # Section of the partner-facing integration guide, e.g. "§3.1".
    doc_ref: str
    severity: CheckSeverity
    passed: bool
    detail: str = ""


class HttpTranscript(BaseModel):
    """A redacted record of one HTTP exchange with the partner's servers."""

    method: str
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    status_code: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    error: str | None = None
    elapsed_ms: int | None = None


class StepStatus(StrEnum):
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"


class Step(BaseModel):
    step_id: str
    title: str
    doc_ref: str
    started_at: datetime
    checks: list[CheckResult] = Field(default_factory=list)
    http: list[HttpTranscript] = Field(default_factory=list)
    note: str = ""

    @property
    def status(self) -> StepStatus:
        if any(c.severity == CheckSeverity.FAIL and not c.passed for c in self.checks):
            return StepStatus.FAILED
        if any(c.severity == CheckSeverity.WARN and not c.passed for c in self.checks):
            return StepStatus.WARNING
        return StepStatus.PASSED


class TokenAuthMethod(StrEnum):
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_POST = "client_secret_post"
    # Public client: PKCE only, no client secret.
    NONE = "none"


class Partner(BaseModel):
    id: str
    slug: str
    name: str
    client_id: str
    client_secret_encrypted: str | None
    token_auth_method: TokenAuthMethod
    expected_iss: str | None
    dashboard_token_hash: str
    created_at: datetime
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at


class LaunchMode(StrEnum):
    EHR = "ehr"
    STANDALONE = "standalone"


class RunStatus(StrEnum):
    AWAITING_AUTHORIZATION = "awaiting_authorization"
    AUTHORIZED = "authorized"
    FAILED = "failed"


class Run(BaseModel):
    id: str
    partner_id: str
    created_at: datetime
    updated_at: datetime
    launch_mode: LaunchMode
    iss: str
    status: RunStatus
    oauth_state: str | None = None
    pkce_verifier: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    tokens_encrypted: str | None = None
    patient_id: str | None = None
    encounter_id: str | None = None
    fhir_user: str | None = None
    note_sent_count: int = 0
    steps: list[Step] = Field(default_factory=list)

    @property
    def overall_status(self) -> StepStatus:
        statuses = [s.status for s in self.steps]
        if StepStatus.FAILED in statuses:
            return StepStatus.FAILED
        if StepStatus.WARNING in statuses:
            return StepStatus.WARNING
        return StepStatus.PASSED


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_step(step_id: str, title: str, doc_ref: str) -> Step:
    return Step(step_id=step_id, title=title, doc_ref=doc_ref, started_at=utc_now())
