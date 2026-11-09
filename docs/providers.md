# Providers: SAST engine, SCA, Snyk, JFrog, SonarQube

slsec is OSS-first. The defaults need no accounts: Opengrep for SAST and osv-scanner for SCA.
Snyk, JFrog and SonarQube plug in where your org already licenses them. Commands below are
shown for **PowerShell** and **bash**; the hooks themselves are Python wrappers and behave the
same on Windows, macOS and Linux.

Pick providers in `.slsec.yaml` (or with `slsec init`):

```yaml
mode: warn
strict: false
providers:
  sast_engine: opengrep   # opengrep | semgrep | none
  sca: osv                # osv | snyk | jfrog | none
```

```bash
slsec init --profile java,docker --sca snyk --sast-engine opengrep
```

| Area | Where it runs | Default | Alternatives |
|---|---|---|---|
| SAST | commit stage, staged files, offline | Opengrep (`slsec-sast`) | Semgrep CE |
| SCA | pre-push stage, only when a manifest/lockfile changed | osv-scanner (`slsec-osv`) | Snyk (`slsec-snyk`), JFrog (`slsec-jfrog`) |
| Deep SAST / quality gate | CI | none | SonarQube (no hook, see below), Snyk Code in the IDE |

## `mode`, `strict` and what blocks

* `mode: warn` (default): findings are printed, the hook exits 0. `mode: block`: findings from
  the provider hooks (SAST and SCA) fail the commit/push. Secrets always block.
* **Missing or unauthenticated tools are not findings.** If the Snyk or JFrog CLI is not
  installed, has no credentials, or the machine is offline, the hook prints a clear warning
  and exits 0, and CI does the enforcing. Set `strict: true` in `.slsec.yaml` (or
  `SLSEC_STRICT=1` in the environment) to fail instead. The same applies to the SAST engine:
  a failed download or a broken rule is "unavailable", not clean.
* **CI is strict by default.** Both CI templates set `SLSEC_STRICT=1` (`strict` input / option,
  default `true`), which overrides `.slsec.yaml`. An expired token, a missing secret or a broken
  scanner then fails the build instead of silently turning the scan off. While rolling out
  provider tokens, pass `strict: false` to the CI template.
* `strict` is about the tool being unavailable; `mode` is about findings. They are independent.

```yaml
mode: block     # findings fail the hook
strict: true    # a missing/unauthenticated provider also fails the hook
```

---

## SAST: Opengrep (default) or Semgrep CE

Both engines run the same bundled rule packs, per language profile, over staged files only.

### Switching engines

```yaml
providers:
  sast_engine: semgrep   # or opengrep
```

or `slsec init --sast-engine semgrep`. Run `slsec init --update` afterwards to refresh the
generated hook config.

| | Opengrep (default) | Semgrep CE |
|---|---|---|
| License | LGPL-2.1 | LGPL-2.1 engine; registry rules under the Semgrep Rules License |
| How it is installed | slsec downloads the pinned release binary for your OS/arch, verifies a baked-in SHA-256, and caches it | `pip` extra: `slsec[semgrep]` (installed by pre-commit) |
| Windows | Native binary (keep `opengrep.exe` and its DLLs together) | Works through the Python package; check your Python version support |
| Network | Needed once, to fetch the binary (unless pre-provided) | Needed once, to install the package; scans run with `--metrics=off` |

Opengrep is a fork of Semgrep CE (v1.100.0) and reads Semgrep rules unchanged.
Sources: <https://github.com/opengrep/opengrep>, <https://semgrep.dev/docs/getting-started/cli>.

To install Opengrep manually (for example to try it before using the hook), per its README:

```powershell
irm https://raw.githubusercontent.com/opengrep/opengrep/main/install.ps1 | iex
```

```bash
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
```

### Offline and air-gapped

* **Pre-provide the binary.** Download the Opengrep release for your platform from an approved
  source (for example mirrored into an Artifactory generic repository), verify it, and point
  slsec at it. slsec will use it instead of downloading:

  ```powershell
  $env:SLSEC_OPENGREP_PATH = "C:\tools\opengrep\opengrep.exe"
  ```

  ```bash
  export SLSEC_OPENGREP_PATH=/opt/opengrep/opengrep
  ```

* **Cache location.** `SLSEC_CACHE_DIR` moves slsec's tool cache (downloaded binaries). Point it
  at a shared or pre-populated directory on build agents and locked-down laptops.
* **Proxies.** Set the standard `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` environment variables
  for the one-time download; pre-commit and pip honor them as well. Use your internal PyPI
  mirror (`PIP_INDEX_URL`) for the Semgrep extra and for pre-commit's own environments.
* **Scans are offline.** The bundled rule packs are vendored, so no rule download or metrics
  call happens at scan time.

### How the vendored rules relate to the Semgrep Rules License

* The bundled packs are vendored unmodified from the **opengrep-rules** project. That project
  inherits the license of the pre-December-2024 semgrep-rules: **LGPL-2.1 with the Commons
  Clause v1.0** condition (licensor: Semgrep, Inc.). Commons Clause does not restrict internal
  use or free redistribution. It does withhold the right to "Sell": providing a paid product or
  service whose value derives entirely or substantially from the rules. The license text, the
  LGPL text and the provenance notice ship in `src/slsec/configs/sast-rules/` (`LICENSE`,
  `COPYING.LGPL-2.1`, `NOTICE`). Everything else in slsec is Apache-2.0.
* The Semgrep registry rules at semgrep.dev are under the **Semgrep Rules License v1.0**, which
  allows use for your own internal business purposes but not redistribution or offering them as
  a service, and requires notices to stay intact
  (<https://semgrep.dev/legal/rules-license/>). slsec does not vendor those rules.
* Running Semgrep CE as the engine over slsec's vendored rule packs does **not** pull in the
  registry rules. If your team adds registry rules to its own config, that use is covered by the
  Semgrep Rules License, so check it with your legal team.
* This is engineering guidance, not legal advice.

---

## SCA: osv-scanner (OSS default)

No account, no token. The `slsec-osv` hook runs at **pre-push**, only when a manifest or
lockfile changed (`package-lock.json`, `pom.xml`, `go.sum`, `requirements*.txt`, ...). In CI
(`--all-files`) it scans every manifest and writes `slsec-osv.sarif`.

```yaml
providers:
  sca: osv
```

It queries the public OSV database, so the first run needs network. For offline use, osv-scanner
supports downloading local databases (`--offline-vulnerabilities --download-offline-databases`);
see <https://google.github.io/osv-scanner/usage/offline-mode/>. Usage and output formats
(including `--format sarif`): <https://google.github.io/osv-scanner/usage/>,
<https://google.github.io/osv-scanner/output/>.

---

## Snyk

```yaml
providers:
  sca: snyk
```

### Install the CLI

The hook uses the Snyk CLI. If your pre-commit config installs it for you, nothing more is
needed; otherwise install it yourself (<https://docs.snyk.io/developer-tools/snyk-cli/install-or-update-the-snyk-cli>):

```powershell
# npm (Node.js 12+, npm 7+)
npm install snyk -g

# Scoop
scoop bucket add snyk https://github.com/snyk/scoop-snyk
scoop install snyk

# Standalone: download https://static.snyk.io/cli/latest/snyk-win.exe, rename it to snyk.exe,
# put it in a permanent folder on PATH.
```

```bash
npm install snyk -g
# or Homebrew
brew tap snyk/tap && brew install snyk/tap/snyk
# or standalone (Linux): curl --compressed https://downloads.snyk.io/cli/stable/snyk-linux -o snyk
```

Verify with `snyk --version`. (A winget package is not covered by the vendor install page, so
it is not listed here.)

### Authenticate

(<https://docs.snyk.io/developer-tools/snyk-cli/authenticate-to-use-the-cli>)

| Where | How |
|---|---|
| Laptop | `snyk auth` (browser OAuth). Stores credentials locally |
| Laptop or CI | `SNYK_TOKEN` environment variable with a personal access token / API token |
| CI (recommended) | A **service account** token in the `SNYK_TOKEN` secret, so the pipeline survives a person leaving. A service account OAuth token goes in `SNYK_OAUTH_TOKEN` instead |

```powershell
$env:SNYK_TOKEN = "<token>"       # current session only
snyk auth                         # or interactive login
```

If your account is not on the default region, run `snyk config environment SNYK-EU-01` (or
`SNYK-US-02`, `SNYK-AU-01`) before authenticating.

### What the hook runs

`slsec-snyk` runs at **pre-push**, only when a manifest or lockfile changed. It runs
`snyk test` (open-source dependency scan) and writes `slsec-snyk.sarif` when `SLSEC_REPORT_DIR`
is set (CI). Relevant `snyk test` behavior: exit 0 = clean, 1 = vulnerabilities found, 2 = CLI
failure, 3 = no supported projects (<https://docs.snyk.io/developer-tools/snyk-cli/commands/test>).

**If Snyk is missing or unauthenticated** the hook prints a warning and exits 0; CI enforces.
With `strict: true` it fails instead. In `mode: warn` vulnerabilities are shown but do not block;
`mode: block` fails the push.

### Snyk Code belongs in the IDE

Snyk Code (SAST) is too slow for a commit hook. Use the Snyk plugin for VS Code, JetBrains IDEs
or Visual Studio for as-you-type SAST and dependency results
(<https://docs.snyk.io/developer-tools/snyk-ide-plugins-and-extensions>). Use the commit-stage
`slsec-sast` hook for the fast baseline and Snyk Code in the IDE and CI for depth.

### CI secret

GitHub Actions: create a repository (or organization) secret `SNYK_TOKEN` and pass it to the
reusable workflow explicitly:

```yaml
jobs:
  slsec:
    uses: kston83/shift-left-security/.github/workflows/slsec-reusable.yml@v0.2.0
    permissions: { contents: read, security-events: write }
    secrets:
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

Jenkins: add a "Secret text" credential and pass `slsecScan(snykTokenCredentialsId: 'snyk-token')`.
It is bound as `SNYK_TOKEN` around the pre-push stage only. See [ci.md](ci.md).

---

## JFrog (Artifactory / Xray)

```yaml
providers:
  sca: jfrog
```

### Install and configure `jf`

(<https://docs.jfrog.com/integrations/docs/jfrog-cli-command-reference>)

```powershell
# Windows: the installer script is shell based, so use the vendor's Windows download
# (JFrog CLI install page) or your internal package source, then:
jf --version
```

```bash
curl -fL https://install-cli.jfrog.io | sh
jf --version
```

Add your platform once per machine, then select it:

```bash
jf c add my-server --url=https://acme.jfrog.io --access-token=<token>   # `jf config add`
jf c use my-server
```

Use an **access token**, not a password, and a token scoped to what the audit needs. `jf options`
lists every environment variable the CLI honors. For headless use, `JF_URL` + `JF_ACCESS_TOKEN`
in the environment is the pattern the `jfrog/setup-jfrog-cli` action documents
(<https://github.com/jfrog/setup-jfrog-cli>).

### What the hook runs

`slsec-jfrog` runs at **pre-push**, only when manifests changed, and calls `jf audit` using your
existing `jf` configuration. In CI it writes `slsec-jfrog.sarif` (`jf audit` supports `--format sarif`).
Same degradation as Snyk: no `jf`, no configured server, or offline means a warning and exit 0
unless `strict: true`.

`jf audit` capabilities
(<https://docs.jfrog.com/security/docs/scan-your-source-code>):

* **With Xray:** SCA of your dependencies (CVEs, licenses, operational risk). `--watches`,
  `--project` or `--repo-path` scope results to your Xray policies; `--min-severity` and
  `--fixable-only` narrow output. With `--fail` at its default, a matching Fail Build rule gives
  exit code 3.
* **Advanced Security tier:** contextual analysis (reachability), secrets, IaC and SAST scanners
  (`--secrets`, `--iac`, `--sast`, and `--sca` to select scanners individually). Which of these
  your platform can run depends on your JFrog entitlement; confirm with your JFrog admin or
  `jf audit --help`. Output formats: `table`, `json`, `simple-json`, `sarif`, `cyclonedx`.

### CI: access token or OIDC

* **Access token:** store `JF_URL` and `JF_ACCESS_TOKEN` as secrets and pass them to the reusable
  workflow; set `install-jfrog-cli: true` so the job installs `jf` (pinned
  `jfrog/setup-jfrog-cli`):

  ```yaml
  jobs:
    slsec:
      uses: kston83/shift-left-security/.github/workflows/slsec-reusable.yml@v0.2.0
      permissions: { contents: read, security-events: write }
      with:
        install-jfrog-cli: true
      secrets:
        JF_URL: ${{ secrets.JF_URL }}
        JF_ACCESS_TOKEN: ${{ secrets.JF_ACCESS_TOKEN }}
  ```

* **OIDC (no long-lived token):** `jfrog/setup-jfrog-cli` supports GitHub OIDC with
  `oidc-provider-name` and `permissions: id-token: write`, with only `JF_URL` set
  (CLI 2.75.0 or later). The reusable workflow does not request `id-token`, to keep its
  permissions minimal; for OIDC, run your own job with `setup-jfrog-cli` and `jf audit`, or use
  Frogbot.
* **Jenkins:** `slsecScan(jfrogUrlCredentialsId: 'jfrog-url', jfrogTokenCredentialsId: 'jfrog-access-token')`.

### Frogbot for pull requests

[Frogbot](https://github.com/jfrog/frogbot) (<https://docs.jfrog.com/security/docs/frogbot>)
scans pull requests and commits for SCA, SAST, IaC and secrets issues and comments on the PR.
It complements the pre-push hook: the hook catches problems on the laptop, Frogbot reviews the PR
with the full Xray policy. Check the Frogbot docs for the current Xray version and token
permission requirements before rolling it out.

### JFrog Curation (phase 3)

If Artifactory is already your package gateway, enable **JFrog Curation** on the remote
repositories to block malicious or risky open-source packages at download time, before they
reach a laptop or build agent. This is on the slsec phase 3 roadmap (supply-chain guard) and is
configured in the JFrog platform, not in slsec.

---

## SonarQube: no hook, by design

SonarQube analysis runs on the server, scans the whole project (often with a build) and takes
minutes. That does not fit a commit hook. The shift-left options are:

1. **SonarQube for IDE in connected mode** (formerly SonarLint) in the editor, using the same
   rules as the server.
2. **The CI quality gate**, which is the enforcement point.

slsec's contribution is the CI wiring (below) and the `slsec-sast` baseline in the commit stage.

### SonarQube for IDE, connected mode

Connected mode binds your local project to a SonarQube Server (or Cloud) project so the IDE uses
the server's **quality profile** and settings (file exclusions, analyzer parameters). The IDE
matches the server branch to your checked-out git branch. For shared setup, one team member
exports the binding into the repository (a `.sonarlint` JSON file) and others are prompted to bind.

Create a **user token** on the SonarQube account page. Project, global and organization-scoped
tokens do not work for connected mode.

| IDE | Setup |
|---|---|
| **VS Code** | Activity Bar > SONARQUBE SETUP > CONNECTED MODE > *Add SonarQube Server Connection* (URL, user token, connection name) > *Save Connection*. Then bind: accept the detected project or choose *Add Project Binding* and pick the remote project. To share: export from the CONNECTED MODE view, commit the `.sonarlint` file. Teammates select *Use Configuration* then *Save Connection And Bind Project* (each with their own token). |
| **IntelliJ** | Use the connection wizard in the SonarQube for IDE settings, then bind the project to the server project. Quality profile and settings sync as above; shared binding needs SonarQube Server 10.5+. |
| **Visual Studio** | Use the connection wizard, then bind the solution. The extension periodically syncs the project's quality profile from the server. |

Vendor docs: VS Code <https://docs.sonarsource.com/sonarqube-for-vs-code/connect-your-ide/setup/>;
IntelliJ <https://docs.sonarsource.com/sonarqube-for-intellij/team-features/connected-mode/>;
Visual Studio <https://docs.sonarsource.com/sonarqube-for-visual-studio/team-features/connected-mode/>.
Exact menu labels for IntelliJ and Visual Studio differ by version; follow the vendor setup page
for your IDE version.

`slsec doctor` prints a reminder to set up connected mode whenever a language profile
(java, node, python, go, dotnet) is detected in the repo.

### CI quality gate

* **GitHub Actions:** reusable workflow input `sonarqube: true` plus `SONAR_TOKEN` and
  `SONAR_HOST_URL` secrets. It runs `SonarSource/sonarqube-scan-action`, then
  `SonarSource/sonarqube-quality-gate-action`. Java (Maven/Gradle) and .NET need the
  build-integrated scanners instead of the CLI scanner action; see [ci.md](ci.md).
* **Jenkins / CloudBees CI:** `slsecScan(sonar: [enabled: true, installation: 'SonarQube'])`
  runs the analysis inside `withSonarQubeEnv`, then `waitForQualityGate`. This needs the
  SonarQube webhook pointing at `<jenkins>/sonarqube-webhook/` configured on the server
  (<https://docs.sonarsource.com/sonarqube-server/latest/devops-platform-integration/jenkins-integration/>).

---

## Reference

* OWASP DevSecOps Guideline: <https://owasp.org/www-project-devsecops-guideline/>
* [tool-selection.md](tool-selection.md), [owasp-mapping.md](owasp-mapping.md), [ci.md](ci.md),
  [rollout.md](rollout.md)
