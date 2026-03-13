# Contributor Onboarding & Setup

You need `python >= 3.10`.

## 1. Local Development Setup

```bash
git clone https://github.com/viishal-001/Cloudguard_CLI.git
cd Cloudguard_CLI

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)

# Install CloudGuard in editable mode with development dependencies
pip install -e ".[dev]"
```

## 2. Running Tests (pytest + moto)

CloudGuard uses `pytest` for testing and `moto` to mock AWS APIs.

```bash
# Run all tests
pytest -q

# Run tests with coverage report
pytest tests/ --cov=cloudguard --cov-report=term-missing
```

## 3. Running CI Locally

Before opening a PR, run the same checks GitHub Actions runs:

```bash
# 1. Lint and Format (ruff)
ruff check cloudguard/ tests/
ruff format cloudguard/ tests/

# 2. Type Check (mypy)
mypy cloudguard/ --ignore-missing-imports

# 3. Security Audit (bandit & safety)
bandit -r cloudguard/ -ll
safety check

# 4. Tests
pytest -q
```

## 4. Contributing Workflow

1. Discuss major changes in an Issue first.
2. Create a branch from `develop`.
3. Adhere to our [SECURITY Policy](SECURITY.md).
4. Do NOT commit real AWS credentials or secrets.
5. Use the provided Pull Request template (.github/PULL_REQUEST_TEMPLATE.md).
6. Ensure CI passes locally before pushing.

## 5. Adding a New Scanner

1. Read `cloudguard_prd.md` to ensure the service is supported.
2. Create `cloudguard/rules/<service>_rules.yaml`.
3. Create `cloudguard/scanners/<service>_scanner.py`, inheriting from `BaseScanner` and decorated with `@register_scanner`.
4. Import the new scanner module in `cloudguard/cli.py` to trigger registration.
5. Write unit tests using `moto` in `tests/test_<service>_scanner.py`.
