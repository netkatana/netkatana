FROM ghcr.io/astral-sh/uv:python3.14-alpine

ENV UV_PYTHON_DOWNLOADS=never
ENV UV_PYTHON=python3

WORKDIR /app

COPY . .

RUN uv sync --no-dev --no-cache

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["netkatana"]
