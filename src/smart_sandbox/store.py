"""SQLite persistence for partner registrations and runs.

Single-replica service: SQLite on a persistent volume is the whole story.
Client secrets and OAuth tokens are stored encrypted (see crypto.SecretBox);
dashboard tokens are stored hashed.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from smart_sandbox.models import Partner, Run, Step

metadata = MetaData()

partners = Table(
    "partner",
    metadata,
    Column("id", String, primary_key=True),
    Column("slug", String, unique=True, nullable=False, index=True),
    Column("name", String, nullable=False),
    Column("client_id", String, nullable=False),
    Column("client_secret_encrypted", String, nullable=True),
    Column("token_auth_method", String, nullable=False),
    Column("expected_iss", String, nullable=True),
    Column("dashboard_token_hash", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)

runs = Table(
    "run",
    metadata,
    Column("id", String, primary_key=True),
    Column(
        "partner_id",
        String,
        ForeignKey("partner.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    ),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("launch_mode", String, nullable=False),
    Column("iss", String, nullable=False),
    Column("status", String, nullable=False),
    Column("oauth_state", String, nullable=True, index=True),
    Column("pkce_verifier", String, nullable=True),
    Column("authorization_endpoint", String, nullable=True),
    Column("token_endpoint", String, nullable=True),
    Column("tokens_encrypted", Text, nullable=True),
    Column("patient_id", String, nullable=True),
    Column("encounter_id", String, nullable=True),
    Column("fhir_user", String, nullable=True),
    Column("note_sent_count", Integer, nullable=False, default=0),
    Column("steps_json", Text, nullable=False, default="[]"),
)


def _as_utc(value: datetime) -> datetime:
    # SQLite loses tzinfo on round-trip; every stored datetime is UTC.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _partner_from_row(row: Row[Any]) -> Partner:
    return Partner(
        id=row.id,
        slug=row.slug,
        name=row.name,
        client_id=row.client_id,
        client_secret_encrypted=row.client_secret_encrypted,
        token_auth_method=row.token_auth_method,
        expected_iss=row.expected_iss,
        dashboard_token_hash=row.dashboard_token_hash,
        created_at=_as_utc(row.created_at),
        expires_at=_as_utc(row.expires_at),
    )


def _run_from_row(row: Row[Any]) -> Run:
    steps = [Step.model_validate(s) for s in json.loads(row.steps_json)]
    return Run(
        id=row.id,
        partner_id=row.partner_id,
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
        launch_mode=row.launch_mode,
        iss=row.iss,
        status=row.status,
        oauth_state=row.oauth_state,
        pkce_verifier=row.pkce_verifier,
        authorization_endpoint=row.authorization_endpoint,
        token_endpoint=row.token_endpoint,
        tokens_encrypted=row.tokens_encrypted,
        patient_id=row.patient_id,
        encounter_id=row.encounter_id,
        fhir_user=row.fhir_user,
        note_sent_count=row.note_sent_count,
        steps=steps,
    )


def _run_values(run: Run) -> dict[str, object]:
    return {
        "partner_id": run.partner_id,
        "created_at": run.created_at,
        "updated_at": run.updated_at,
        "launch_mode": run.launch_mode.value,
        "iss": run.iss,
        "status": run.status.value,
        "oauth_state": run.oauth_state,
        "pkce_verifier": run.pkce_verifier,
        "authorization_endpoint": run.authorization_endpoint,
        "token_endpoint": run.token_endpoint,
        "tokens_encrypted": run.tokens_encrypted,
        "patient_id": run.patient_id,
        "encounter_id": run.encounter_id,
        "fhir_user": run.fhir_user,
        "note_sent_count": run.note_sent_count,
        "steps_json": json.dumps([s.model_dump(mode="json") for s in run.steps]),
    }


class Store:
    def __init__(self, db_path: str) -> None:
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._engine: AsyncEngine = create_async_engine(
            f"sqlite+aiosqlite:///{db_path}"
        )

    async def connect(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    # --- Partners ---

    async def create_partner(self, partner: Partner) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(partners).values(
                    id=partner.id,
                    slug=partner.slug,
                    name=partner.name,
                    client_id=partner.client_id,
                    client_secret_encrypted=partner.client_secret_encrypted,
                    token_auth_method=partner.token_auth_method.value,
                    expected_iss=partner.expected_iss,
                    dashboard_token_hash=partner.dashboard_token_hash,
                    created_at=partner.created_at,
                    expires_at=partner.expires_at,
                )
            )

    async def get_partner_by_slug(self, slug: str) -> Partner | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(partners).where(partners.c.slug == slug))
            ).first()
        if row is None:
            return None
        partner = _partner_from_row(row)
        if partner.is_expired:
            await self.delete_partner(partner.id)
            return None
        return partner

    async def get_partner_by_id(self, partner_id: str) -> Partner | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(partners).where(partners.c.id == partner_id))
            ).first()
        return _partner_from_row(row) if row is not None else None

    async def delete_partner(self, partner_id: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(delete(runs).where(runs.c.partner_id == partner_id))
            await conn.execute(delete(partners).where(partners.c.id == partner_id))

    async def count_partners(self) -> int:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(select(partners.c.id))).all()
        return len(rows)

    # --- Runs ---

    async def create_run(self, run: Run) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(insert(runs).values(id=run.id, **_run_values(run)))

    async def update_run(self, run: Run) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                update(runs).where(runs.c.id == run.id).values(**_run_values(run))
            )

    async def get_run(self, run_id: str) -> Run | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(select(runs).where(runs.c.id == run_id))).first()
        return _run_from_row(row) if row is not None else None

    async def find_run_by_state(self, oauth_state: str) -> Run | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(runs).where(runs.c.oauth_state == oauth_state)
                )
            ).first()
        return _run_from_row(row) if row is not None else None

    async def list_runs(self, partner_id: str, limit: int = 50) -> list[Run]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(runs)
                    .where(runs.c.partner_id == partner_id)
                    .order_by(runs.c.created_at.desc())
                    .limit(limit)
                )
            ).all()
        return [_run_from_row(row) for row in rows]
