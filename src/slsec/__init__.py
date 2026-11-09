"""Shift-left security toolkit: drop-in pre-commit hooks and shared policy."""

__version__ = "0.1.0"

# Where consuming repos fetch the slsec hooks from. Change this once the repo
# is hosted (GitHub, GitHub Enterprise, internal Git server, ...).
# Can be overridden per run with `slsec init --source-url` or SLSEC_SOURCE_URL.
DEFAULT_SOURCE_URL = "https://github.com/kston83/shift-left-security"
