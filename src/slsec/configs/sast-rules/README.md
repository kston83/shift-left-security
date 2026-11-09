# Vendored SAST rule packs

Commit-stage Semgrep-syntax rules for the `slsec-sast` hook (Opengrep by
default, Semgrep CE optional). Vendored, unmodified, from
[opengrep-rules](https://github.com/opengrep/opengrep-rules); see `NOTICE`
(source, commit) and `LICENSE` / `COPYING.LGPL-2.1`.

**License boundary:** this directory is LGPL-2.1 with the Commons Clause
condition (upstream's terms). Everything else in the repo is Apache-2.0.

## Layout

| Path | What |
|---|---|
| `<pack>/` | Per-rule files, byte-for-byte upstream, upstream subpaths kept. Packs: `java`, `kotlin`, `javascript` (includes the TypeScript rules under `javascript/typescript/`), `python`, `go`, `csharp`. |
| `bundles/<pack>.yaml` | Generated: all rules of a pack in one file (see below). |
| `allowlist.yaml` | Source of truth for the curation: upstream path + rule ids per pack, plus the `rejected` list. |
| `MANIFEST.txt` | Every included rule id and its upstream path. |
| `SOURCE`, `NOTICE`, `LICENSE`, `COPYING.LGPL-2.1` | Provenance and licensing. |

Refresh with `python scripts/refresh-sast-rules.py --ref <commit|tag>`. It
re-copies only allowlisted files, regenerates the bundles and provenance files,
and reports rules removed or renamed upstream and new upstream rules that meet
the criteria below (to review, then add to `allowlist.yaml` or `rejected`).

## Selection criteria

Aim: fast, low-noise, high-signal at commit time, on staged files only.

Included when ALL hold (automated in the refresh script, then hand-pruned):

- `severity` is `ERROR` or `WARNING`; `confidence` is `MEDIUM` or `HIGH`;
  `category: security`.
- CWE is in an OWASP Top 10 oriented set: injection (SQL 89, command 78,
  LDAP 90, XPath 643, code 94/95, SSTI 1336), XSS (79/116), deserialization
  (502), XXE (611), weak crypto/hashing (326-329, 338, 780), hardcoded JWT or
  session secrets (798/522), SSRF (918), path traversal (22/23/73), TLS and
  certificate validation (295/297), open redirect (601), JWT misuse
  (287/347), debug mode (489).
- Does not need cross-file context (`interfile` rules are excluded).
- Pattern is not unusually large (guard against expensive generic matchers).
- Mainstream frameworks only: Spring, Servlet/JAX-RS, Express, Django, Flask,
  net/http, ASP.NET. Niche stacks are excluded (AWS Lambda, Angular, Pyramid,
  Deno, Twilio, Intercom, Android, CDK, JBoss, ...).

Excluded: `INFO`/audit-style rules, `confidence: LOW` rules (this drops
several useful but noisy ones such as `eval-detected`, `avoid-pickle`,
`insecure-urlopen`), correctness/best-practice/performance rules, cookie and
header hygiene rules, and anything in `rejected`.

A file is vendored only if every rule in it passes, because files are copied
verbatim.

Kotlin has few upstream security rules (6 vendored); Java rules do not apply
to `.kt` files.

## Why bundles

Opengrep/Semgrep load a directory of rule files slowly on Windows. Measured
with Opengrep 1.33.1 on this repo's python pack (84 rules): 11.8 s as a
directory versus 5.3 s as one file. The bundle only rewrites each rule `id` to
`<pack>.<dotted.dirs>.<id>`, which is what the engine assigns in directory mode,
so findings are identical. Engines prepend the config location to ids; match
with `check_id == id or check_id.endswith("." + id)`.

## Notes for the hook

- Pass staged files explicitly. A directory scan skips `tests/`, `test/` etc.
  via the default `.semgrepignore`.
- Opengrep 1.33.1 has no `--metrics` flag (Semgrep does); use
  `--disable-version-check` on both engines.
- The pre-commit config of the consumer repo should exclude this directory
  from `trailing-whitespace` / `end-of-file-fixer`: some upstream files have
  trailing whitespace and would be rewritten.
