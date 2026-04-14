FROM ghcr.io/astral-sh/uv:python3.14-alpine

# Install tlsx v1.2.2
COPY --from=projectdiscovery/tlsx@sha256:8a3298106704f50d0ef1049fe70ed26fe1605a9c9cde0064beb1f80071bf4dbc /usr/local/bin/tlsx /usr/local/bin/

ENV UV_PYTHON_DOWNLOADS=never
ENV UV_PYTHON=python3

WORKDIR /app

COPY . .

RUN uv sync --no-dev --no-cache

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["netkatana"]
