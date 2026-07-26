init:
	uv venv --python=3.12
	uv sync
	uvx pre-commit install

test:
	# TODO

train:
	uv run bloom-hash train "abcdefghijklmnopqrstuvwxyz0123456789 " 2