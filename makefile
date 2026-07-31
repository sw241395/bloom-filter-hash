init:
	uv venv --python=3.12
	uv sync
	uv pip install -e .
	uvx pre-commit install

test:
	# TODO


train:
	uv run bloom-hash train "abcdefghijklmnopqrstuvwxyz" 2 --hash-alg sha256

break: 
	uv run bloom-hash break fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603 --hash-alg sha256