init:
	uv venv --python=3.12
	uv sync
	uv pip install -e .
	uvx pre-commit install

test:
	uv run pytest