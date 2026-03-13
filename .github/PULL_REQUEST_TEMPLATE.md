# Pull Request

## Description
Provide a brief overview of the changes in this PR. If it resolves an issue, link to it (e.g., "Fixes #123").

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security fix/audit

## Checklist (Required)
- [ ] I have read the `CONTRIBUTING.md` document
- [ ] My code follows the code style of this project (`ruff check` passes)
- [ ] I have run tests locally (`pytest`) and they all pass
- [ ] I have added tests that prove my fix is effective or my feature works
- [ ] I have checked for security issues (`bandit -r cloudguard/` and `safety check`)
- [ ] I have updated the documentation accordingly (README, RULES.md, etc.)

## Security Audit (Required)
- [ ] I confirm this change does NOT introduce hardcoded secrets or credentials.
- [ ] I confirm this change adheres to the "Read-Only by default" requirement (no destructive AWS calls).

## Additional Context
Add any other context or screenshots about the PR here.
