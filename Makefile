.PHONY: install dev test lint format clean docker-build docker-test

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

coverage:
	pytest tests/ --cov=cloudguard --cov-report=term-missing --cov-report=html

lint:
	ruff check cloudguard/ tests/

format:
	ruff format cloudguard/ tests/

typecheck:
	mypy cloudguard/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov dist build *.egg-info

docker-build:
	docker build -t cloudguard:latest .

docker-test:
	docker-compose run --rm test
