.PHONY: help clean install test test-cov lint format format-check type-check docstrings docs build check-dist dev-install ci conformance ci-docker

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

clean: ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf docs/_build/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

install: ## Install package
	uv pip install -e .

dev-install: ## Install package with development dependencies
	uv sync --all-groups --all-extras
	uv run pre-commit install

test: ## Run tests
	uv run pytest

test-cov: ## Run tests with coverage
	uv run pytest --cov=pip_fund --cov-report=html --cov-report=term

lint: ## Run linter
	uv run ruff check .

format: ## Format code
	uv run ruff format .
	uv run ruff check --fix .

format-check: ## Check formatting
	uv run ruff format --check .

type-check: ## Run type checker
	uv run pyright

docstrings: ## Check docstring signatures
	uvx pydoclint src/pip_fund

docs: ## Build documentation with warnings as errors
	uv run sphinx-build -W -b html docs docs/_build/html

build: ## Build package
	uv build --clear

check-dist: build ## Validate distribution metadata
	uv run twine check dist/*

ci: lint format-check type-check docstrings test docs check-dist ## Run CI checks

conformance: ## Check py-canon conformance
	uvx preen check --strict

ci-docker: ## Run CI in a standard Python container
	docker run --rm -v "$(CURDIR):/work" -w /work python:3.13 sh -c 'pip install uv && UV_PROJECT_ENVIRONMENT=/tmp/pip-fund-env uv sync --all-groups --all-extras && UV_PROJECT_ENVIRONMENT=/tmp/pip-fund-env make ci'
