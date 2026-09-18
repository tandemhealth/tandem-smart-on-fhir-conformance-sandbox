"""Conformance-run orchestration: each flow appends checked steps to a run
and persists it. Routes stay thin wrappers around these functions."""

import json
import uuid

from smart_sandbox.checks import Checker
from smart_sandbox.config import Settings
from smart_sandbox.crypto import SecretBox
from smart_sandbox.fhir import (
    SAMPLE_CONDITIONS,
    build_condition,
    build_document_reference,
    check_create_response,
    read_encounter,
    read_patient,
)
from smart_sandbox.http import SafeResponse, safe_request
from smart_sandbox.jsonval import as_object
from smart_sandbox.models import (
    LaunchMode,
    Partner,
    Run,
    RunStatus,
    Step,
    new_step,
    utc_now,
)
from smart_sandbox.smart import (
    build_authorization_redirect,
    discover,
    exchange_code,
    extract_fhir_user,
    refresh_tokens,
)
from smart_sandbox.store import Store


def redirect_uri(settings: Settings) -> str:
    return settings.SANDBOX_PUBLIC_BASE_URL.rstrip("/") + "/smart/callback"


def normalize_iss(iss: str) -> str:
    return iss.strip().rstrip("/")


def iss_matches_registration(partner: Partner, iss: str) -> bool:
    """The launch iss decides which host receives the partner's client secret,
    so it must equal the FHIR base URL pinned at registration. A registration
    without one (legacy rows) never matches."""
    if not partner.expected_iss:
        return False
    return normalize_iss(iss) == normalize_iss(partner.expected_iss)


def _client_secret(box: SecretBox, partner: Partner) -> str | None:
    if partner.client_secret_encrypted is None:
        return None
    return box.decrypt(partner.client_secret_encrypted)


def _decrypt_tokens(box: SecretBox, run: Run) -> dict[str, object] | None:
    if run.tokens_encrypted is None:
        return None
    data: object = json.loads(box.decrypt(run.tokens_encrypted))
    return as_object(data)


def _store_tokens(box: SecretBox, run: Run, tokens: dict[str, object]) -> None:
    run.tokens_encrypted = box.encrypt(json.dumps(tokens))


def _launch_params_step(
    *,
    partner: Partner,
    iss: str,
    launch: str | None,
    allow_private: bool,
) -> Step:
    step = new_step("launch", "Launch parameters", "§2")
    checker = Checker(step)
    checker.check(
        "launch.iss_tls",
        "iss is an https:// FHIR base URL",
        "§2.1, §7",
        iss.startswith("https://") or (allow_private and iss.startswith("http://")),
        detail=f"iss: {iss}",
    )
    # Enforced by the launch route before a run exists; recorded here so the
    # report documents what was verified.
    checker.check(
        "launch.iss_expected",
        "iss matches the FHIR base URL registered for this sandbox client",
        "§2.1",
        iss_matches_registration(partner, iss),
        detail=f"Registered: {partner.expected_iss}",
    )
    if launch is not None:
        checker.info(
            "launch.token",
            "EHR launch with a one-time launch token",
            "§2.1",
            "The launch token must be opaque and single-use; the launch context "
            "must only be resolvable via the token endpoint (never in the URL).",
        )
    else:
        checker.info(
            "launch.standalone",
            "Standalone launch (no launch token)",
            "§2.2",
            "The authorization server is expected to prompt for the "
            "patient/encounter context.",
        )
    return step


async def start_launch(
    *,
    store: Store,
    box: SecretBox,
    settings: Settings,
    partner: Partner,
    iss: str,
    launch: str | None,
) -> tuple[Run, str | None]:
    """Handle a launch request; returns the run and, when the partner's
    discovery document passed validation, the authorization redirect URL."""
    allow_private = settings.SANDBOX_ALLOW_PRIVATE_NETWORK
    launch_mode = LaunchMode.EHR if launch is not None else LaunchMode.STANDALONE
    now = utc_now()
    run = Run(
        id=str(uuid.uuid4()),
        partner_id=partner.id,
        created_at=now,
        updated_at=now,
        launch_mode=launch_mode,
        iss=iss,
        status=RunStatus.AWAITING_AUTHORIZATION,
    )
    run.steps.append(
        _launch_params_step(
            partner=partner, iss=iss, launch=launch, allow_private=allow_private
        )
    )

    smart_config, discovery_step = await discover(
        iss, launch_mode=launch_mode, allow_private=allow_private
    )
    run.steps.append(discovery_step)

    redirect_url: str | None = None
    if smart_config is None:
        run.status = RunStatus.FAILED
    else:
        url, state, verifier, authorize_step = build_authorization_redirect(
            partner=partner,
            smart_config=smart_config,
            iss=iss,
            launch=launch,
            redirect_uri=redirect_uri(settings),
        )
        run.steps.append(authorize_step)
        run.oauth_state = state
        run.pkce_verifier = verifier
        run.authorization_endpoint = str(smart_config["authorization_endpoint"])
        run.token_endpoint = str(smart_config["token_endpoint"])
        redirect_url = url

    run.updated_at = utc_now()
    await store.create_run(run)
    return run, redirect_url


async def handle_callback(
    *,
    store: Store,
    box: SecretBox,
    settings: Settings,
    partner: Partner,
    run: Run,
    code: str | None,
    error: str | None,
    error_description: str | None,
) -> Run:
    """Handle the authorization redirect: token exchange + context reads."""
    allow_private = settings.SANDBOX_ALLOW_PRIVATE_NETWORK
    # The state is single-use: consume it before doing anything else.
    run.oauth_state = None

    if error is not None or code is None:
        step = new_step("callback", "Authorization callback", "§3.3")
        Checker(step).check(
            "callback.code",
            "The authorization server redirected back with a code",
            "§3.2",
            False,
            detail=f"error: {error!r}, error_description: {error_description!r}",
        )
        run.steps.append(step)
        run.status = RunStatus.FAILED
        run.updated_at = utc_now()
        await store.update_run(run)
        return run

    assert run.token_endpoint is not None
    assert run.pkce_verifier is not None
    tokens, token_step = await exchange_code(
        partner=partner,
        client_secret=_client_secret(box, partner),
        token_endpoint=run.token_endpoint,
        code=code,
        code_verifier=run.pkce_verifier,
        redirect_uri=redirect_uri(settings),
        launch_mode=run.launch_mode,
        allow_private=allow_private,
    )
    run.steps.append(token_step)
    run.pkce_verifier = None

    if tokens is None:
        run.status = RunStatus.FAILED
        run.updated_at = utc_now()
        await store.update_run(run)
        return run

    _store_tokens(box, run, tokens)
    run.patient_id = str(tokens.get("patient"))
    encounter = tokens.get("encounter")
    run.encounter_id = str(encounter) if encounter else None
    run.fhir_user = extract_fhir_user(tokens)
    run.status = RunStatus.AUTHORIZED

    access_token = str(tokens["access_token"])
    _, patient_step = await read_patient(
        iss=run.iss,
        access_token=access_token,
        patient_id=run.patient_id,
        allow_private=allow_private,
    )
    run.steps.append(patient_step)

    if run.encounter_id is not None:
        _, encounter_step = await read_encounter(
            iss=run.iss,
            access_token=access_token,
            encounter_id=run.encounter_id,
            patient_id=run.patient_id,
            fhir_user=run.fhir_user,
            allow_private=allow_private,
        )
        run.steps.append(encounter_step)

    run.updated_at = utc_now()
    await store.update_run(run)
    return run


async def _post_resource_with_refresh(
    *,
    box: SecretBox,
    settings: Settings,
    partner: Partner,
    run: Run,
    step: Step,
    url: str,
    body: dict[str, object],
) -> tuple[SafeResponse | None, str]:
    """POST a FHIR resource; on 401, refresh the access token and retry once
    (the guide's §6 behavior). Refresh evidence lands on the same step."""
    allow_private = settings.SANDBOX_ALLOW_PRIVATE_NETWORK
    tokens = _decrypt_tokens(box, run)
    assert tokens is not None
    checker = Checker(step)

    def headers(access_token: object) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/fhir+json",
            "Accept": "application/fhir+json",
        }

    response, transcripts = await safe_request(
        "POST",
        url,
        headers=headers(tokens["access_token"]),
        json_body=body,
        allow_private=allow_private,
    )
    step.http.extend(transcripts)
    error = transcripts[-1].error or ""

    refresh_token = tokens.get("refresh_token")
    if (
        response is not None
        and response.status_code == 401
        and refresh_token
        and run.token_endpoint is not None
    ):
        checker.info(
            "writeback.refresh_retry",
            "Access token rejected (401); refreshing and retrying",
            "§6",
            "This mirrors production Tandem: a 401 triggers one refresh + retry.",
        )
        new_tokens, refresh_step = await refresh_tokens(
            partner=partner,
            client_secret=_client_secret(box, partner),
            token_endpoint=run.token_endpoint,
            refresh_token=str(refresh_token),
            allow_private=allow_private,
        )
        step.checks.extend(refresh_step.checks)
        step.http.extend(refresh_step.http)
        if new_tokens is not None:
            tokens = {**tokens, **new_tokens}
            _store_tokens(box, run, tokens)
            response, transcripts = await safe_request(
                "POST",
                url,
                headers=headers(tokens["access_token"]),
                json_body=body,
                allow_private=allow_private,
            )
            step.http.extend(transcripts)
            error = transcripts[-1].error or ""
    return response, error


async def send_note(
    *,
    store: Store,
    box: SecretBox,
    settings: Settings,
    partner: Partner,
    run: Run,
) -> Run:
    """Write back the sample note and diagnoses (guide §5)."""
    assert run.patient_id is not None
    retry = run.note_sent_count > 0
    base = run.iss.rstrip("/")

    title = "Write back DocumentReference"
    doc_step = new_step(
        "writeback_document",
        title + (" (idempotent retry)" if retry else ""),
        "§5.1",
    )
    document = build_document_reference(
        patient_id=run.patient_id,
        encounter_id=run.encounter_id,
        fhir_user=run.fhir_user,
        encounter=None,
    )
    response, error = await _post_resource_with_refresh(
        box=box,
        settings=settings,
        partner=partner,
        run=run,
        step=doc_step,
        url=f"{base}/DocumentReference",
        body=document,
    )
    check_create_response(
        Checker(doc_step), "DocumentReference", response, error=error, retry=retry
    )
    run.steps.append(doc_step)

    condition_step = new_step(
        "writeback_conditions",
        "Write back Conditions" + (" (idempotent retry)" if retry else ""),
        "§5.2",
    )
    for index, (code, display, text) in enumerate(SAMPLE_CONDITIONS):
        condition = build_condition(
            code=code,
            display=display,
            text=text,
            patient_id=run.patient_id,
            encounter_id=run.encounter_id,
            fhir_user=run.fhir_user,
        )
        response, error = await _post_resource_with_refresh(
            box=box,
            settings=settings,
            partner=partner,
            run=run,
            step=condition_step,
            url=f"{base}/Condition",
            body=condition,
        )
        check_create_response(
            Checker(condition_step),
            f"Condition[{index}]",
            response,
            error=error,
            retry=retry,
        )
    run.steps.append(condition_step)

    run.note_sent_count += 1
    run.updated_at = utc_now()
    await store.update_run(run)
    return run


async def test_refresh(
    *,
    store: Store,
    box: SecretBox,
    settings: Settings,
    partner: Partner,
    run: Run,
) -> Run:
    """Exercise the refresh-token flow and verify the new token works (§3.5)."""
    allow_private = settings.SANDBOX_ALLOW_PRIVATE_NETWORK
    tokens = _decrypt_tokens(box, run)
    assert tokens is not None

    refresh_token = tokens.get("refresh_token")
    if not refresh_token or run.token_endpoint is None:
        step = new_step("refresh", "Refresh token exchange", "§3.5")
        Checker(step).check(
            "refresh.available",
            "A refresh token is available for this run",
            "§3.5",
            False,
            detail="The token response did not include a refresh_token.",
        )
        run.steps.append(step)
    else:
        new_tokens, refresh_step = await refresh_tokens(
            partner=partner,
            client_secret=_client_secret(box, partner),
            token_endpoint=run.token_endpoint,
            refresh_token=str(refresh_token),
            allow_private=allow_private,
        )
        run.steps.append(refresh_step)
        if new_tokens is not None:
            tokens = {**tokens, **new_tokens}
            _store_tokens(box, run, tokens)
            if run.patient_id is not None:
                _, patient_step = await read_patient(
                    iss=run.iss,
                    access_token=str(tokens["access_token"]),
                    patient_id=run.patient_id,
                    allow_private=allow_private,
                )
                patient_step.title = "Read Patient with the refreshed token"
                run.steps.append(patient_step)

    run.updated_at = utc_now()
    await store.update_run(run)
    return run
