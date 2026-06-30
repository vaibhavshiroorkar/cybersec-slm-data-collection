# syntax=docker/dockerfile:1
# Container image for the corpus build (runs as ECS Fargate tasks via Prefect).
#
# Ordered for layer caching: the dependency set and the Chromium browser are
# installed BEFORE the source is copied, so editing code rebuilds only the final
# (fast) project-install layer — not the heavy dependency/browser layers. uv's
# download cache is kept in a BuildKit cache mount, so it speeds rebuilds without
# bloating the image.
FROM python:3.13-slim

# uv (fast resolver/installer) from the official image.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    CYBERSEC_SLM_DATA_ROOT=/work \
    CYBERSEC_SLM_ENFORCE_ALLOWLIST=1

WORKDIR /app

# ca-certificates: TLS for httpx (sources / NVD / HuggingFace).  git: the
# provenance manifest stamps the commit via `git rev-parse`.  Clean apt lists.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# ── Phase 1: dependencies only (cached unless pyproject.toml / uv.lock change) ──
# `--no-install-project` installs the dependency set without the project itself,
# so a source edit never re-resolves the lock or reinstalls the (heavy) deps.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra orchestration --no-install-project

# Chromium for the HTML crawler (scrape_html). Installed before the source copy
# so it is cached independently of code changes; --with-deps adds the OS libraries
# it needs. Re-downloads only when the lockfile (hence playwright) changes.
RUN .venv/bin/playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# ── Phase 2: the project itself (the only layer a code change rebuilds) ─────────
# Installed editable (uv default) so the package resolves sources/allowlist.yaml
# from /app/sources via its __file__ — do not switch to a site-packages install.
COPY src ./src
COPY sources ./sources
COPY dvc.yaml .dvcignore prefect.yaml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra orchestration

# ── Unprivileged runtime user ──────────────────────────────────────────────────
# Read access to /app + the browser cache is enough (root-created, world-readable).
# Only /work (outputs: data/ + logs/) and /app/src (editable .pyc cache) need to be
# writable, so chown just those — avoids duplicating the multi-GB venv into a
# `chown -R` layer.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /work \
    && chown -R app:app /work /app/src
USER app

VOLUME ["/work"]

# Default: full local build. The Prefect ECS worker overrides the command to run
# the flow; secrets are injected at runtime from AWS Secrets Manager (not baked in).
# --no-sync: the environment is fully built at image time, so never re-sync on start.
ENTRYPOINT ["uv", "run", "--no-sync"]
CMD ["cybersec-slm", "all"]
