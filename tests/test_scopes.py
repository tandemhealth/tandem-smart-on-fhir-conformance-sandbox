"""scopes_supported is compared by coverage, not by literal string equality:
real servers advertise wildcards and SMART v2 syntax."""

import pytest
from httpx import AsyncClient

from smart_sandbox.smart import SCOPES, scope_is_covered
from tests.conftest import RunLaunch
from tests.mock_ehr import MockEhrConfig


@pytest.mark.parametrize(
    ("requested", "advertised", "covered"),
    [
        ("patient/Patient.read", {"patient/Patient.read"}, True),
        ("patient/Patient.read", {"patient/*.*"}, True),  # v1 wildcard
        ("patient/Patient.read", {"patient/*.read"}, True),
        ("patient/Patient.read", {"patient/*.rs"}, True),  # v2 wildcard
        ("patient/Patient.read", {"patient/Patient.cruds"}, True),
        ("patient/Condition.write", {"patient/*.cud"}, True),
        ("patient/Condition.write", {"patient/*.c"}, False),  # write needs c+u+d
        ("patient/Patient.read", {"patient/*.r"}, False),  # read needs r+s
        ("patient/Patient.read", {"user/*.*"}, False),  # other context
        ("patient/Patient.read", {"patient/Observation.*"}, False),
        ("patient/Patient.read", {"patient/*.rs?category=vital-signs"}, False),
        ("openid", {"patient/*.*"}, False),  # non-resource scopes: literal only
        ("launch", {"launch"}, True),
    ],
)
def test_scope_is_covered(requested: str, advertised: set[str], covered: bool) -> None:
    assert scope_is_covered(requested, advertised) is covered


def test_every_requested_scope_is_covered_by_the_launcher_style_wildcards() -> None:
    # The SMART Health IT launcher's actual scopes_supported (2026-09-16).
    advertised = {
        "openid",
        "profile",
        "fhirUser",
        "launch",
        "launch/patient",
        "launch/encounter",
        "patient/*.*",
        "user/*.*",
        "offline_access",
    }
    assert all(scope_is_covered(s, advertised) for s in SCOPES)


class TestWildcardScopesPassDiscovery:
    @pytest.fixture
    def mock_ehr_config(self) -> MockEhrConfig:
        return MockEhrConfig(advertise_wildcard_scopes=True)

    async def test_scope_check_passes(
        self, client: AsyncClient, run_launch: RunLaunch
    ) -> None:
        run_id = await run_launch()
        page = await client.get(f"/runs/{run_id}")
        assert 'data-check-result="discovery.scopes:pass"' in page.text
