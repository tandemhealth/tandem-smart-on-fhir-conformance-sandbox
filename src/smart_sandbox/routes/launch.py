"""SMART launch entry point and OAuth callback."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from smart_sandbox import flows
from smart_sandbox.config import Settings
from smart_sandbox.crypto import SecretBox
from smart_sandbox.dependencies import get_box, get_settings, get_store
from smart_sandbox.ratelimit import RateLimiter, enforce
from smart_sandbox.store import Store
from smart_sandbox.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter()

_launch_limiter = RateLimiter(limit=30, window_seconds=60)


def _not_found(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "message": "Unknown sandbox partner. Register at the sandbox "
            "landing page to get a launch URL.",
            "status_code": 404,
        },
        status_code=404,
    )


@router.get("/smart/{slug}/launch")
async def launch(
    request: Request,
    slug: Annotated[str, Path(max_length=64)],
    store: Annotated[Store, Depends(get_store)],
    box: Annotated[SecretBox, Depends(get_box)],
    settings: Annotated[Settings, Depends(get_settings)],
    iss: Annotated[str, Query(min_length=1, max_length=2000)],
    launch: Annotated[str | None, Query(max_length=4000)] = None,
) -> Response:
    """SMART App Launch entry point (guide §2): the partner's EHR opens this
    URL with iss (+ launch for EHR launch); the sandbox then runs discovery
    and redirects the browser to the partner's authorization endpoint."""
    enforce(_launch_limiter, request)
    partner = await store.get_partner_by_slug(slug)
    if partner is None or partner.is_expired:
        return _not_found(request)
    if not flows.iss_matches_registration(partner, iss):
        # The iss determines where the registered client secret is sent, so a
        # launch from anywhere but the pinned FHIR base is refused outright
        # rather than recorded as a run.
        logger.warning("Sandbox launch refused (iss mismatch): partner=%s", partner.id)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "message": "The launch iss does not match the FHIR base URL "
                "registered for this sandbox client. Create a new registration "
                "to test a different EHR.",
                "status_code": 403,
            },
            status_code=403,
        )

    run, redirect_url = await flows.start_launch(
        store=store,
        box=box,
        settings=settings,
        partner=partner,
        iss=iss,
        launch=launch,
    )
    logger.info(
        "Sandbox launch started: partner=%s run=%s mode=%s",
        partner.id,
        run.id,
        run.launch_mode.value,
    )
    if redirect_url is None:
        # Discovery failed conformance; show the report instead of bouncing
        # the clinician's browser to a broken authorization endpoint.
        return RedirectResponse(url=f"/runs/{run.id}", status_code=303)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.get("/smart/callback")
async def callback(
    request: Request,
    store: Annotated[Store, Depends(get_store)],
    box: Annotated[SecretBox, Depends(get_box)],
    settings: Annotated[Settings, Depends(get_settings)],
    state: Annotated[str | None, Query(max_length=200)] = None,
    code: Annotated[str | None, Query(max_length=4000)] = None,
    error: Annotated[str | None, Query(max_length=500)] = None,
    error_description: Annotated[str | None, Query(max_length=2000)] = None,
) -> Response:
    """OAuth redirect URI (guide §3.3): exchanges the code, validates the
    launch context, reads Patient + Encounter, then shows the run report."""
    if state is None:
        return _not_found(request)
    run = await store.find_run_by_state(state)
    if run is None:
        # Unknown or already-consumed state: fail closed without confirming
        # whether such a run ever existed.
        return _not_found(request)
    partner = await store.get_partner_by_id(run.partner_id)
    if partner is None or partner.is_expired:
        return _not_found(request)

    run = await flows.handle_callback(
        store=store,
        box=box,
        settings=settings,
        partner=partner,
        run=run,
        code=code,
        error=error,
        error_description=error_description,
    )
    logger.info(
        "Sandbox callback processed: partner=%s run=%s status=%s",
        partner.id,
        run.id,
        run.status.value,
    )
    return RedirectResponse(url=f"/runs/{run.id}", status_code=303)
