from httpx import ASGITransport, AsyncClient

from smart_sandbox.api import app
from smart_sandbox.jsonval import as_object
from tests.conftest import RunLaunch
from tests.mock_ehr import ISS, MockEhrState


async def test_ehr_launch_happy_path(
    client: AsyncClient, run_launch: RunLaunch, mock_ehr: MockEhrState
) -> None:
    # WHEN the partner EHR launches the sandbox and authorization completes
    run_id = await run_launch()

    # THEN the report shows every step passed
    page = await client.get(f"/runs/{run_id}")
    assert page.status_code == 200
    assert 'data-overall-status="passed"' in page.text
    assert 'data-step-status="failed"' not in page.text
    assert "SMART configuration discovery" in page.text
    assert "Token exchange" in page.text
    assert "Read Patient" in page.text
    assert "Read Encounter" in page.text

    # AND the authorization request carried the SMART launch parameters
    authorize = mock_ehr.authorize_requests[0]
    assert authorize["aud"] == ISS
    assert authorize["launch"] == "launch-token-1"
    assert "launch" in authorize["scope"].split()
    assert authorize["code_challenge_method"] == "S256"

    # AND no secrets leak into the rendered transcripts
    assert "sandbox-client-secret" not in page.text
    for token_request in mock_ehr.token_requests:
        access_like = [v for v in token_request.values() if v.startswith("at-")]
        assert not access_like


async def test_standalone_launch_omits_launch_scope(
    client: AsyncClient, run_launch: RunLaunch, mock_ehr: MockEhrState
) -> None:
    run_id = await run_launch(launch=None)

    page = await client.get(f"/runs/{run_id}")
    assert page.status_code == 200
    assert "Standalone launch" in page.text

    authorize = mock_ehr.authorize_requests[0]
    assert "launch" not in authorize
    assert "launch" not in authorize["scope"].split()


async def test_callback_with_unknown_state_is_rejected(client: AsyncClient) -> None:
    response = await client.get(
        "/smart/callback", params={"state": "unknown", "code": "x"}
    )
    assert response.status_code == 404


async def test_state_is_single_use(
    client: AsyncClient, run_launch: RunLaunch, mock_ehr: MockEhrState
) -> None:
    await run_launch()
    # Replaying the callback with the consumed state fails closed.
    state = mock_ehr.authorize_requests[0]["state"]
    replay = await client.get(
        "/smart/callback", params={"state": state, "code": "replayed"}
    )
    assert replay.status_code == 404


async def test_write_back_and_idempotent_retry(
    client: AsyncClient, run_launch: RunLaunch, mock_ehr: MockEhrState
) -> None:
    run_id = await run_launch()

    # WHEN sending the test note
    response = await client.post(f"/runs/{run_id}/send-note")
    assert response.status_code == 303
    page = await client.get(f"/runs/{run_id}")
    assert "Write back DocumentReference" in page.text
    assert "Write back Conditions" in page.text
    assert 'data-step-status="failed"' not in page.text

    # THEN one DocumentReference and two Conditions were created
    types = [r["resourceType"] for r in mock_ehr.created_resources]
    assert types == ["DocumentReference", "Condition", "Condition"]
    document = mock_ehr.created_resources[0]
    assert document["subject"] == {"reference": "Patient/abc123"}
    context = as_object(document["context"])
    assert context is not None
    assert context.get("encounter") == [{"reference": "Encounter/enc-123"}]

    # AND a second send is reported as the idempotency retry
    again = await client.post(f"/runs/{run_id}/send-note")
    assert again.status_code == 303
    page = await client.get(f"/runs/{run_id}")
    assert "idempotent retry" in page.text
    assert 'data-step-status="failed"' not in page.text


async def test_refresh_token_flow(
    client: AsyncClient, run_launch: RunLaunch, mock_ehr: MockEhrState
) -> None:
    run_id = await run_launch()

    response = await client.post(f"/runs/{run_id}/refresh")
    assert response.status_code == 303
    assert mock_ehr.refresh_count == 1

    page = await client.get(f"/runs/{run_id}")
    assert "Refresh token exchange" in page.text
    assert "Read Patient with the refreshed token" in page.text
    assert 'data-step-status="failed"' not in page.text


async def test_write_back_requires_authorized_run(
    client: AsyncClient, run_launch: RunLaunch
) -> None:
    response = await client.post("/runs/nonexistent/send-note")
    assert response.status_code == 404


async def test_report_link_alone_cannot_spend_credentials(
    client: AsyncClient, run_launch: RunLaunch, mock_ehr: MockEhrState
) -> None:
    # GIVEN an authorized run whose report URL has been shared
    run_id = await run_launch()

    # WHEN someone without the owner's dashboard cookie opens it
    stranger = AsyncClient(
        transport=ASGITransport(app=app), base_url=str(client.base_url)
    )
    async with stranger:
        page = await stranger.get(f"/runs/{run_id}")
        # THEN they can read the report but are not offered the actions
        assert page.status_code == 200
        assert 'data-overall-status="passed"' in page.text
        assert f"/runs/{run_id}/send-note" not in page.text
        assert f"/runs/{run_id}/refresh" not in page.text

        # AND posting the actions directly fails closed without touching the EHR
        for action in ("send-note", "refresh"):
            denied = await stranger.post(f"/runs/{run_id}/{action}")
            assert denied.status_code == 404, action
    assert mock_ehr.created_resources == []
    assert mock_ehr.refresh_count == 0

    # WHILE the owner (cookie set at registration) still can
    page = await client.get(f"/runs/{run_id}")
    assert f"/runs/{run_id}/send-note" in page.text
    assert (await client.post(f"/runs/{run_id}/refresh")).status_code == 303
    assert mock_ehr.refresh_count == 1
