"""Each partner-side contract violation surfaces as a failed check with the
right guide reference on the run report."""

import pytest
from httpx import AsyncClient

from tests.conftest import RunLaunch
from tests.mock_ehr import MockEhrConfig, MockEhrState


class TestDiscoveryWithoutPkce:
    @pytest.fixture
    def mock_ehr_config(self) -> MockEhrConfig:
        return MockEhrConfig(omit_pkce_support=True)

    async def test_launch_stops_at_discovery(
        self, client: AsyncClient, run_launch: RunLaunch
    ) -> None:
        run_id = await run_launch()
        page = await client.get(f"/runs/{run_id}")
        assert page.status_code == 200
        assert 'data-check-result="discovery.pkce:fail"' in page.text
        assert 'data-overall-status="failed"' in page.text
        # The browser was never redirected to the authorization endpoint.
        assert "Token exchange" not in page.text


class TestMissingEncounterContext:
    @pytest.fixture
    def mock_ehr_config(self) -> MockEhrConfig:
        return MockEhrConfig(omit_encounter_context=True)

    async def test_ehr_launch_fails_encounter_check(
        self, client: AsyncClient, run_launch: RunLaunch
    ) -> None:
        run_id = await run_launch()
        page = await client.get(f"/runs/{run_id}")
        assert 'data-check-result="token.encounter:fail"' in page.text
        assert 'data-overall-status="failed"' in page.text


class TestEncounterSubjectMismatch:
    @pytest.fixture
    def mock_ehr_config(self) -> MockEhrConfig:
        return MockEhrConfig(encounter_wrong_subject=True)

    async def test_subject_check_fails(
        self, client: AsyncClient, run_launch: RunLaunch
    ) -> None:
        run_id = await run_launch()
        page = await client.get(f"/runs/{run_id}")
        assert 'data-check-result="encounter.subject:fail"' in page.text
        assert 'data-overall-status="failed"' in page.text


class TestMissingRefreshToken:
    @pytest.fixture
    def mock_ehr_config(self) -> MockEhrConfig:
        return MockEhrConfig(omit_refresh_token=True)

    async def test_warned_not_failed(
        self, client: AsyncClient, run_launch: RunLaunch
    ) -> None:
        run_id = await run_launch()
        page = await client.get(f"/runs/{run_id}")
        # offline_access is a warning-level deviation, not a hard failure.
        assert 'data-check-result="token.refresh_token:fail"' in page.text
        assert 'data-overall-status="warning"' in page.text
        assert 'data-step-status="failed"' not in page.text


class TestWritebackWithoutLocation:
    @pytest.fixture
    def mock_ehr_config(self) -> MockEhrConfig:
        return MockEhrConfig(writeback_omit_location=True)

    async def test_location_check_fails(
        self, client: AsyncClient, run_launch: RunLaunch
    ) -> None:
        run_id = await run_launch()
        await client.post(f"/runs/{run_id}/send-note")
        page = await client.get(f"/runs/{run_id}")
        assert (
            'data-check-result="writeback.documentreference.location:fail"' in page.text
        )
        assert 'data-overall-status="failed"' in page.text


class TestWritebackWrongStatus:
    @pytest.fixture
    def mock_ehr_config(self) -> MockEhrConfig:
        return MockEhrConfig(writeback_status=200)

    async def test_status_check_fails(
        self, client: AsyncClient, run_launch: RunLaunch
    ) -> None:
        run_id = await run_launch()
        await client.post(f"/runs/{run_id}/send-note")
        page = await client.get(f"/runs/{run_id}")
        assert (
            'data-check-result="writeback.documentreference.status:fail"' in page.text
        )
        assert 'data-overall-status="failed"' in page.text


class TestExpiredTokenRefreshRetry:
    async def test_401_triggers_refresh_and_retry(
        self,
        client: AsyncClient,
        run_launch: RunLaunch,
        mock_ehr: MockEhrState,
    ) -> None:
        run_id = await run_launch()
        # The EHR expires every issued access token mid-encounter.
        mock_ehr.valid_access_tokens.clear()
        await client.post(f"/runs/{run_id}/send-note")
        page = await client.get(f"/runs/{run_id}")
        # The 401 -> refresh -> retry path succeeded end to end.
        assert mock_ehr.refresh_count >= 1
        assert "refreshing and retrying" in page.text
        assert 'data-step-status="failed"' not in page.text
