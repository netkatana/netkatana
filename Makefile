test:
	uv run pytest -vv --cov=netkatana --cov-report=term-missing

lint:
	uv run ruff format --check
	uv run ruff check

format:
	uv run ruff format
	uv run ruff check --fix
