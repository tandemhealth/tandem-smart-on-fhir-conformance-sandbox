import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import RequestResponseEndpoint

from smart_sandbox.config import settings
from smart_sandbox.crypto import SecretBox
from smart_sandbox.errors import register_exception_handlers
from smart_sandbox.routes import launch, pages
from smart_sandbox.store import Store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    app.state.settings = settings
    app.state.box = SecretBox(settings.SANDBOX_SECRETS_KEY)
    store = Store(settings.SANDBOX_DB_PATH)
    await store.connect()
    app.state.store = store
    try:
        yield
    finally:
        await store.close()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
register_exception_handlers(app)

_access_logger = logging.getLogger("smart_sandbox.access")


@app.middleware("http")
async def _access_log(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Access log without the query string: the dashboard bootstrap token and
    the OAuth callback's code and state travel in query parameters."""
    response = await call_next(request)
    _access_logger.info(
        "%s %s %d", request.method, request.url.path, response.status_code
    )
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "OK"}


app.include_router(pages.router)
app.include_router(launch.router)
