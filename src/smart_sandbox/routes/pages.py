"""Self-service registration, partner dashboard, and run report pages."""

import logging
import secrets
import urllib.parse
import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Path, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from smart_sandbox import flows
from smart_sandbox.config import Settings
from smart_sandbox.crypto import (
    SecretBox,
    hash_token,
    new_url_token,
    token_matches_hash,
)
from smart_sandbox.dependencies import get_box, get_settings, get_store
from smart_sandbox.models import Partner, Run, RunStatus, TokenAuthMethod, utc_now
from smart_sandbox.ratelimit import RateLimiter, enforce
from smart_sandbox.store import Store
from smart_sandbox.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter()

_register_limiter = RateLimiter(limit=10, window_seconds=60)
_action_limiter = RateLimiter(limit=60, window_seconds=60)

_COOKIE_PREFIX = "sandbox_dashboard_"


def _error_page(request: Request, status_code: int, message: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "error.html",
        {"message": message, "status_code": status_code},
        status_code=status_code,
    )


def _not_found(request: Request) -> HTMLResponse:
    return _error_page(
        request, 404, "This sandbox registration or run does not exist (or expired)."
    )


def _is_valid_iss(iss: str, settings: Settings) -> bool:
    parsed = urllib.parse.urlsplit(iss)
    allowed_schemes = (
        ("https", "http") if settings.SANDBOX_ALLOW_PRIVATE_NETWORK else ("https",)
    )
    return (
        parsed.scheme in allowed_schemes
        and bool(parsed.hostname)
        and not parsed.query
        and not parsed.fragment
    )


async def _authorized_partner(
    request: Request, store: Store, slug: str
) -> Partner | None:
    """Resolve the partner iff the dashboard cookie for this slug is valid."""
    partner = await store.get_partner_by_slug(slug)
    if partner is None:
        return None
    cookie = request.cookies.get(_COOKIE_PREFIX + slug)
    if cookie is None or not token_matches_hash(cookie, partner.dashboard_token_hash):
        return None
    return partner


@router.get("/", response_class=HTMLResponse)
async def index(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {"redirect_uri": flows.redirect_uri(settings)},
    )


@router.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    store: Annotated[Store, Depends(get_store)],
    box: Annotated[SecretBox, Depends(get_box)],
    settings: Annotated[Settings, Depends(get_settings)],
    name: Annotated[str, Form(min_length=1, max_length=200)],
    client_id: Annotated[str, Form(min_length=1, max_length=500)],
    token_auth_method: Annotated[TokenAuthMethod, Form()],
    expected_iss: Annotated[str, Form(min_length=1, max_length=2000)],
    client_secret: Annotated[str, Form(max_length=2000)] = "",
) -> Response:
    enforce(_register_limiter, request)
    if token_auth_method != TokenAuthMethod.NONE and not client_secret:
        return _error_page(
            request,
            422,
            "A client secret is required for the selected client "
            "authentication method.",
        )
    expected_iss = flows.normalize_iss(expected_iss)
    if not _is_valid_iss(expected_iss, settings):
        return _error_page(
            request,
            422,
            "The FHIR base URL must be an absolute https:// URL"
            + (
                " (http:// is accepted because private-network mode is on)."
                if settings.SANDBOX_ALLOW_PRIVATE_NETWORK
                else "."
            ),
        )
    if await store.count_partners() >= settings.SANDBOX_MAX_PARTNERS:
        return _error_page(
            request,
            503,
            "The sandbox is at capacity. Please contact Tandem to get set up.",
        )

    dashboard_token = new_url_token()
    now = utc_now()
    partner = Partner(
        id=str(uuid.uuid4()),
        slug=secrets.token_urlsafe(9),
        name=name,
        client_id=client_id,
        client_secret_encrypted=(box.encrypt(client_secret) if client_secret else None),
        token_auth_method=token_auth_method,
        expected_iss=expected_iss,
        dashboard_token_hash=hash_token(dashboard_token),
        created_at=now,
        expires_at=now + timedelta(days=settings.SANDBOX_REGISTRATION_TTL_DAYS),
    )
    await store.create_partner(partner)
    logger.info("Sandbox partner registered: %s", partner.id)

    base = settings.SANDBOX_PUBLIC_BASE_URL.rstrip("/")
    response = templates.TemplateResponse(
        request,
        "registered.html",
        {
            "partner": partner,
            "launch_url": f"{base}/smart/{partner.slug}/launch",
            "redirect_uri": flows.redirect_uri(settings),
            "dashboard_url": f"{base}/p/{partner.slug}",
            "dashboard_token": dashboard_token,
        },
    )
    _set_dashboard_cookie(response, settings, partner.slug, dashboard_token)
    return response


def _set_dashboard_cookie(
    response: Response, settings: Settings, slug: str, token: str
) -> None:
    # Path "/" so the cookie also reaches /runs/<id>/... where the owner
    # triggers write-back and refresh. The name and hash are per slug, so one
    # partner's cookie never authorises another's dashboard, and SameSite
    # Strict keeps cross-site forms from posting the action routes.
    response.set_cookie(
        _COOKIE_PREFIX + slug,
        token,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=settings.SANDBOX_PUBLIC_BASE_URL.startswith("https://"),
        samesite="strict",
        path="/",
    )


@router.get("/p/{slug}", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    slug: Annotated[str, Path(max_length=64)],
    store: Annotated[Store, Depends(get_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    token: Annotated[str | None, Query(max_length=200)] = None,
) -> Response:
    # A token in the query (from the shown-once dashboard link) is exchanged
    # for an HttpOnly cookie so it doesn't linger in the address bar/history.
    if token is not None:
        partner = await store.get_partner_by_slug(slug)
        if partner is None or not token_matches_hash(
            token, partner.dashboard_token_hash
        ):
            return _not_found(request)
        response: Response = RedirectResponse(url=f"/p/{partner.slug}", status_code=303)
        _set_dashboard_cookie(response, settings, partner.slug, token)
        return response

    partner = await _authorized_partner(request, store, slug)
    if partner is None:
        return _not_found(request)
    runs = await store.list_runs(partner.id)
    base = settings.SANDBOX_PUBLIC_BASE_URL.rstrip("/")
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "partner": partner,
            "runs": runs,
            "launch_url": f"{base}/smart/{partner.slug}/launch",
            "redirect_uri": flows.redirect_uri(settings),
            "RunStatus": RunStatus,
        },
    )


@router.post("/p/{slug}/standalone")
async def standalone_launch(
    request: Request,
    slug: Annotated[str, Path(max_length=64)],
    store: Annotated[Store, Depends(get_store)],
) -> Response:
    enforce(_action_limiter, request)
    partner = await _authorized_partner(request, store, slug)
    if partner is None or not partner.expected_iss:
        return _not_found(request)
    logger.info("Sandbox standalone launch requested: %s", partner.id)
    url = f"/smart/{partner.slug}/launch?" + urllib.parse.urlencode(
        {"iss": partner.expected_iss}
    )
    return RedirectResponse(url=url, status_code=303)


@router.post("/p/{slug}/delete")
async def delete_registration(
    request: Request,
    slug: Annotated[str, Path(max_length=64)],
    store: Annotated[Store, Depends(get_store)],
) -> Response:
    partner = await _authorized_partner(request, store, slug)
    if partner is None:
        return _not_found(request)
    await store.delete_partner(partner.id)
    logger.info("Sandbox partner deleted: %s", partner.id)
    return RedirectResponse(url="/", status_code=303)


async def _run_and_partner(store: Store, run_id: str) -> tuple[Run, Partner] | None:
    run = await store.get_run(run_id)
    if run is None:
        return None
    partner = await store.get_partner_by_id(run.partner_id)
    if partner is None or partner.is_expired:
        return None
    return run, partner


def _owns_partner(request: Request, partner: Partner) -> bool:
    """True iff the request carries the partner's dashboard cookie.

    The run id in a report URL is a read capability: anyone with the link can
    view the report. Actions that spend the stored credentials (write-back,
    refresh) additionally require the registration owner's cookie.
    """
    cookie = request.cookies.get(_COOKIE_PREFIX + partner.slug)
    return cookie is not None and token_matches_hash(
        cookie, partner.dashboard_token_hash
    )


@router.get("/runs/{run_id}", response_class=HTMLResponse)
async def run_report(
    request: Request,
    run_id: Annotated[str, Path(max_length=64)],
    store: Annotated[Store, Depends(get_store)],
) -> Response:
    found = await _run_and_partner(store, run_id)
    if found is None:
        return _not_found(request)
    run, partner = found
    return templates.TemplateResponse(
        request,
        "run.html",
        {
            "run": run,
            "partner": partner,
            "can_write_back": run.status == RunStatus.AUTHORIZED
            and _owns_partner(request, partner),
            "RunStatus": RunStatus,
        },
    )


async def _authorized_run_action(
    request: Request, store: Store, run_id: str
) -> tuple[Run, Partner] | Response:
    """Resolve the run for a credential-spending action, or the error page.

    Fails closed with 404 when the caller lacks the owner's dashboard cookie,
    so a leaked report link cannot be used to drive requests at the EHR.
    """
    enforce(_action_limiter, request)
    found = await _run_and_partner(store, run_id)
    if found is None:
        return _not_found(request)
    run, partner = found
    if not _owns_partner(request, partner):
        return _error_page(
            request,
            404,
            "Only the registration owner can run this from the report. Open "
            "the report from your dashboard, in the browser you registered "
            "with, and try again.",
        )
    if run.status != RunStatus.AUTHORIZED or run.tokens_encrypted is None:
        return _error_page(
            request, 409, "This run is not authorized; complete the launch first."
        )
    return run, partner


@router.post("/runs/{run_id}/send-note")
async def send_note(
    request: Request,
    run_id: Annotated[str, Path(max_length=64)],
    store: Annotated[Store, Depends(get_store)],
    box: Annotated[SecretBox, Depends(get_box)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    resolved = await _authorized_run_action(request, store, run_id)
    if isinstance(resolved, Response):
        return resolved
    run, partner = resolved
    logger.info("Sandbox write-back triggered for run %s", run.id)
    await flows.send_note(
        store=store, box=box, settings=settings, partner=partner, run=run
    )
    return RedirectResponse(url=f"/runs/{run.id}", status_code=303)


@router.post("/runs/{run_id}/refresh")
async def refresh(
    request: Request,
    run_id: Annotated[str, Path(max_length=64)],
    store: Annotated[Store, Depends(get_store)],
    box: Annotated[SecretBox, Depends(get_box)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    resolved = await _authorized_run_action(request, store, run_id)
    if isinstance(resolved, Response):
        return resolved
    run, partner = resolved
    logger.info("Sandbox refresh test triggered for run %s", run.id)
    await flows.test_refresh(
        store=store, box=box, settings=settings, partner=partner, run=run
    )
    return RedirectResponse(url=f"/runs/{run.id}", status_code=303)
