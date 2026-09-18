FROM python:3.14-slim-bookworm AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-default-groups --no-install-project

COPY src ./src
COPY README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-default-groups --no-editable

FROM python:3.14-slim-bookworm

RUN useradd -m -u 1000 appuser && mkdir /data && chown appuser:appuser /data
USER appuser
WORKDIR /app

COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    SANDBOX_DB_PATH=/data/smart-sandbox.sqlite3

VOLUME ["/data"]
EXPOSE 8090
CMD ["smart-sandbox", "--host", "0.0.0.0", "--port", "8090"]
