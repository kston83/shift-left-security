# Contributing

## Dev setup

The repo uses [uv](https://docs.astral.sh/uv/). `.python-version` pins the dev Python (3.14), and
`uv.lock` pins every dependency. slsec itself supports Python 3.11+.

```sh
uv sync                                  # .venv with Python 3.14 + the dev group (uv downloads Python if needed)
uv sync --extra semgrep                  # also install Semgrep CE, for the Semgrep half of the SAST tests
uv run pytest                            # unit + integration (real checkov) tests
uv run pytest -m "not integration"       # fast unit tests only
uv run --python 3.11 pytest              # test against the oldest supported Python
uv run pre-commit install                # dogfood this repo's own hooks (pre-commit is in the dev group)
```

After changing dependencies in `pyproject.toml`, run `uv lock` and commit `uv.lock`; CI runs
`uv sync --locked` and fails on a stale lock. Renovate refreshes the lock weekly.

Python 3.15 isn't supported yet: checkov's dependencies (pycares, orjson) and PyYAML don't ship
3.15 wheels. The weekly `py315-canary` job in `self-test.yml` turns green once they do.

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

## Docs

`tests/test_docs.py` keeps the docs honest. It fails when:

* a CLI flag, hook argument, `.slsec.yaml` key, `SLSEC_*` environment variable, workflow input or
  secret, or `slsecScan` option isn't in `docs/reference.md`, or a documented CI default is wrong;
* the README, docs, examples or install scripts reference another slsec version, or pin a hook repo
  or tool to a different version than the profile templates (so a Renovate PR that bumps a template
  pin also has to update `examples/`);
* an internal link or heading anchor in the README, CONTRIBUTING, CHANGELOG or `docs/` is broken.

When you add a flag, input or option, add it to the matching table in `docs/reference.md`.
Command output pasted into the docs comes from real runs; regenerate it rather than editing it.

## Releasing

1. Bump `version` in `pyproject.toml` and `__version__` in `src/slsec/__init__.py`, plus the
   the `vX.Y.Z` references in the README, docs, install scripts, examples and CI templates
   (`slsec-version`, `slsecVersion`). `tests/test_docs.py` fails on any that are left behind.
2. Update `CHANGELOG.md`, and call out any new **blocking** rules.
3. Tag `vX.Y.Z` (signed) and push the tag. Consumers pick it up via Renovate or
   `slsec init --update`.
