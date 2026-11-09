# Contributing

## Dev setup

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"        # Windows: .venv\Scripts\pip install -e ".[dev]"
.venv/bin/pytest                         # unit + integration (real checkov) tests
.venv/bin/pytest -m "not integration"    # fast unit tests only
pre-commit install                       # dogfood this repo's own hooks
```

Try a hook against another repo without releasing:

```sh
cd ../some-repo
pre-commit try-repo ../shift-left-security slsec-checkov --all-files
```

## Layout

| Path | What |
|---|---|
| `.pre-commit-hooks.yaml` | Hooks exported to consumers |
| `src/slsec/hooks/` | Hook wrappers (Python, cross-platform) |
| `src/slsec/configs/` | Shared policy (checkov baseline, gitleaks rules, tool configs) |
| `src/slsec/templates/profiles/` | Profile fragments `slsec init` merges into `.pre-commit-config.yaml` |
| `vars/`, `resources/` | Jenkins shared library (`slsecScan`) |
| `.github/workflows/slsec-reusable.yml` | Reusable GitHub Actions workflow |
| `tests/fixtures/` | Intentionally insecure / secure samples (excluded from dogfood hooks) |

## Changing policy

* **Baseline skips** (`configs/checkov/baseline.yaml`): every entry needs a reason. Removing a
  skip makes a check *blocking* for repos in `mode: block`, so note it in the release notes.
* **Tool pins** live in the profile templates and `.pre-commit-hooks.yaml`. Renovate updates
  them; a test checks that the same upstream repo has the same `rev` in every profile.
* **Never commit real or realistic secrets**, even in tests. Generate them at test time.

## Releasing

1. Bump `version` in `pyproject.toml` and `__version__` in `src/slsec/__init__.py`, plus the
   `v0.1.0` references in the README, docs, install scripts and examples.
2. Update `CHANGELOG.md`, and call out any new **blocking** rules.
3. Tag `vX.Y.Z` (signed) and push the tag. Consumers pick it up via Renovate or
   `slsec init --update`.
