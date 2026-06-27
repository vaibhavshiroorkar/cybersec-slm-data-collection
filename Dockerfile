# Container image for the corpus build (runs as ECS Fargate tasks via Prefect).
FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    CYBERSEC_SLM_DATA_ROOT=/data \
    CYBERSEC_SLM_ENFORCE_ALLOWLIST=1

# uv (fast resolver/installer) from the official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Resolve deps first for layer caching. (Run `uv lock` to refresh uv.lock when
# pyproject changes; drop --frozen below if the lock is intentionally stale.)
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --extra cleaning --extra eda --extra orchestration

# Playwright browser for the HTML crawler (scrape_html)
RUN uv run playwright install --with-deps chromium

COPY sources ./sources
COPY dvc.yaml .dvcignore prefect.yaml ./

VOLUME ["/data"]

# Default: full local build. The Prefect ECS worker overrides the command to run
# the flow; secrets are injected at runtime from AWS Secrets Manager (not baked in).
ENTRYPOINT ["uv", "run"]
CMD ["cybersec-slm", "all"]
