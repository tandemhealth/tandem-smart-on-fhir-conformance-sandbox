"""Error handlers rendering the sandbox's HTML error page.

Unhandled exceptions are logged with their traceback and shown to the browser
as a generic 500; the exception text never reaches the response. HTTPException
detail is shown only for status codes without a message here and only when it
is a plain string, which in this app is always a constant authored by the
sandbox itself.
"""

import logging
from typing import cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.responses import Response

from smart_sandbox.templates import templates

logger = logging.getLogger(__name__)

_STATUS_MESSAGES = {
    404: "That page does not exist.",
    405: "That action is not allowed here.",
    422: "The request was malformed or missing a required field.",
    429: "Too many requests; slow down.",
    500: "The sandbox hit an unexpected error. Check the server log.",
}


def _render(request: Request, status_code: int, message: str) -> Response:
    return templates.TemplateResponse(
        request,
        "error.html",
        {"message": message, "status_code": status_code},
        status_code=status_code,
    )


async def _http_exception(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, HTTPException)
    # Starlette types detail as str, but FastAPI's subclass accepts any JSON.
    detail = cast(object, exc.detail)
    message = _STATUS_MESSAGES.get(exc.status_code) or (
        detail if isinstance(detail, str) and detail else "Request failed."
    )
    return _render(request, exc.status_code, message)


async def _validation_exception(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, RequestValidationError)
    logger.info("Request validation failed: %s %s", request.method, request.url.path)
    return _render(request, 422, _STATUS_MESSAGES[422])


async def _unhandled_exception(request: Request, exc: Exception) -> Response:
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return _render(request, 500, _STATUS_MESSAGES[500])


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, _http_exception)
    app.add_exception_handler(RequestValidationError, _validation_exception)
    app.add_exception_handler(Exception, _unhandled_exception)
