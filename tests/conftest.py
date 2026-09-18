import re
from collections.abc import AsyncGenerator, Callable, Coroutine, Generator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import smart_sandbox.http as safe_http
from smart_sandbox.api import app
from smart_sandbox.config import Settings
from smart_sandbox.crypto import SecretBox
from smart_sandbox.routes import launch as launch_routes, pages as pages_routes
from smart_sandbox.store import Store
from tests.mock_ehr import (
    ISS,
    LAUNCH_TOKEN,
    REGISTRATION_FORM,
    MockEhrConfig,
    MockEhrState,
    create_mock_ehr,
)

SANDBOX_BASE = "http://sandbox.test"


@pytest.fixture(autouse=True)
def _reset_rate_limiters() -> None:  # pyright: ignore[reportUnusedFunction]
    pages_routes._register_limiter.reset()  # pyright: ignore[reportPrivateUsage]
    pages_routes._action_limiter.reset()  # pyright: ignore[reportPrivateUsage]
    launch_routes._launch_limiter.reset()  # pyright: ignore[reportPrivateUsage]


@pytest_asyncio.fixture
async def store() -> AsyncGenerator[Store, None]:
    store = Store(":memory:")
    await store.connect()
    yield store
    await store.close()


@pytest.fixture
def mock_ehr_config() -> MockEhrConfig:
    return MockEhrConfig()


@pytest.fixture
def mock_ehr(mock_ehr_config: MockEhrConfig) -> Generator[MockEhrState, None, None]:
    ehr_app, state = create_mock_ehr(mock_ehr_config)
    previous = safe_http.TEST_TRANSPORT
    safe_http.TEST_TRANSPORT = ASGITransport(app=ehr_app)
    yield state
    safe_http.TEST_TRANSPORT = previous


@pytest_asyncio.fixture
async def client(
    store: Store, mock_ehr: MockEhrState
) -> AsyncGenerator[AsyncClient, None]:
    app.state.settings = Settings(
        SANDBOX_PUBLIC_BASE_URL=SANDBOX_BASE,
        SANDBOX_DB_PATH=":memory:",
        SANDBOX_ALLOW_PRIVATE_NETWORK=False,
    )
    app.state.store = store
    app.state.box = SecretBox(None)
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url=SANDBOX_BASE, follow_redirects=False
    ) as client:
        yield client


@pytest_asyncio.fixture
async def registered_slug(client: AsyncClient) -> str:
    response = await client.post("/register", data=REGISTRATION_FORM)
    assert response.status_code == 200, response.text
    match = re.search(r"/smart/([A-Za-z0-9_-]+)/launch", response.text)
    assert match is not None
    return match.group(1)


RunLaunch = Callable[..., Coroutine[Any, Any, str]]


@pytest.fixture
def run_launch(client: AsyncClient, registered_slug: str) -> RunLaunch:
    """Drive the full browser dance: launch -> authorize -> callback.

    Returns the run id. The mock EHR's authorize endpoint is called through
    the sandbox's test transport, standing in for the clinician's browser.
    """

    async def _run(*, launch: str | None = LAUNCH_TOKEN, iss: str = ISS) -> str:
        params = {"iss": iss}
        if launch is not None:
            params["launch"] = launch
        response = await client.get(f"/smart/{registered_slug}/launch", params=params)
        if response.status_code == 303:
            # Discovery failed; the sandbox sends the browser to the report.
            return response.headers["location"].removeprefix("/runs/")
        assert response.status_code == 302, response.text
        authorize_url = response.headers["location"]

        assert safe_http.TEST_TRANSPORT is not None
        async with AsyncClient(
            transport=safe_http.TEST_TRANSPORT, base_url="https://mock-ehr.example"
        ) as browser:
            ehr_response = await browser.get(authorize_url)
        assert ehr_response.status_code == 302, ehr_response.text
        callback_url = ehr_response.headers["location"]
        assert callback_url.startswith(SANDBOX_BASE + "/smart/callback")

        callback_response = await client.get(callback_url)
        assert callback_response.status_code == 303, callback_response.text
        location = callback_response.headers["location"]
        assert location.startswith("/runs/")
        return location.removeprefix("/runs/")

    return _run
