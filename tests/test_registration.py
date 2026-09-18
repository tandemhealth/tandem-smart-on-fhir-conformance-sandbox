import re

from httpx import ASGITransport, AsyncClient

from smart_sandbox.api import app
from tests.mock_ehr import CLIENT_SECRET, ISS, REGISTRATION_FORM


async def test_register_shows_launch_url_and_dashboard_token(
    client: AsyncClient,
) -> None:
    # WHEN registering a partner
    response = await client.post("/register", data=REGISTRATION_FORM)

    # THEN the page shows the launch URL, redirect URI, and dashboard link
    assert response.status_code == 200
    assert "/smart/" in response.text
    assert "/smart/callback" in response.text
    assert "?token=" in response.text
    # AND the client secret is never echoed back
    assert CLIENT_SECRET not in response.text


async def test_register_requires_secret_for_confidential_clients(
    client: AsyncClient,
) -> None:
    form = {k: v for k, v in REGISTRATION_FORM.items() if k != "client_secret"}
    response = await client.post("/register", data=form)
    assert response.status_code == 422


async def test_register_requires_https_fhir_base(client: AsyncClient) -> None:
    # The registered iss pins where the client secret may be sent, so it is
    # mandatory and must be an absolute https URL.
    missing = {k: v for k, v in REGISTRATION_FORM.items() if k != "expected_iss"}
    assert (await client.post("/register", data=missing)).status_code == 422
    for bad_iss in ("http://ehr.example/fhir", "ehr.example/fhir", "https:///r4"):
        response = await client.post(
            "/register", data={**REGISTRATION_FORM, "expected_iss": bad_iss}
        )
        assert response.status_code == 422, bad_iss


async def test_launch_with_unregistered_iss_is_refused(
    client: AsyncClient, registered_slug: str
) -> None:
    # WHEN the launch names a FHIR base other than the registered one
    response = await client.get(
        f"/smart/{registered_slug}/launch",
        params={"iss": "https://evil.example/fhir", "launch": "x"},
    )

    # THEN it is refused before any discovery request or run is created
    assert response.status_code == 403
    dashboard = await client.get(f"/p/{registered_slug}")
    assert "/runs/" not in dashboard.text

    # AND a trailing slash on the registered base is tolerated
    response = await client.get(
        f"/smart/{registered_slug}/launch", params={"iss": ISS + "/", "launch": "x"}
    )
    assert response.status_code == 302


async def test_dashboard_requires_token_or_cookie(client: AsyncClient) -> None:
    # GIVEN a registration whose page yields the tokened dashboard link
    response = await client.post("/register", data=REGISTRATION_FORM)
    match = re.search(r"/p/([A-Za-z0-9_-]+)\?token=([A-Za-z0-9_-]+)", response.text)
    assert match is not None
    slug, token = match.groups()

    # THEN without cookie or token the dashboard is a 404 (fail closed)
    fresh = AsyncClient(transport=ASGITransport(app=app), base_url=str(client.base_url))
    async with fresh:
        denied = await fresh.get(f"/p/{slug}")
        assert denied.status_code == 404
        wrong = await fresh.get(f"/p/{slug}", params={"token": "wrong-token"})
        assert wrong.status_code == 404

        # AND the tokened link sets the cookie and redirects to a clean URL
        entry = await fresh.get(f"/p/{slug}", params={"token": token})
        assert entry.status_code == 303
        dashboard = await fresh.get(f"/p/{slug}")
        assert dashboard.status_code == 200
        assert "Mock EHR AB" in dashboard.text


async def test_standalone_launch_uses_registered_iss(
    client: AsyncClient, registered_slug: str
) -> None:
    response = await client.post(f"/p/{registered_slug}/standalone")
    assert response.status_code == 303
    assert response.headers["location"].startswith(
        f"/smart/{registered_slug}/launch?iss="
    )
    assert "mock-ehr.example" in response.headers["location"]


async def test_delete_registration_removes_partner(
    client: AsyncClient, registered_slug: str
) -> None:
    # Registration set the dashboard cookie on the client jar.
    response = await client.post(f"/p/{registered_slug}/delete")
    assert response.status_code == 303

    gone = await client.get(f"/p/{registered_slug}")
    assert gone.status_code == 404
    launch = await client.get(f"/smart/{registered_slug}/launch", params={"iss": ISS})
    assert launch.status_code == 404
