/**
 * slsecScan: run the slsec shift-left security checks in Jenkins / CloudBees CI.
 *
 * Runs the same pre-commit hooks developers run locally (over all files) for both the
 * pre-commit stage and the pre-push stage (SCA), then a full-history gitleaks scan, and
 * publishes JUnit + SARIF results. Optionally runs a SonarQube analysis + quality gate.
 *
 *   @Library('slsec@v0.3.0') _
 *   pipeline {
 *     agent { label 'linux' }
 *     stages { stage('Security') { steps { slsecScan() } } }
 *   }
 *
 * Options (all optional): see vars/slsecScan.txt or docs/ci.md.
 * Returns a map: [doctor: <setup check exit code>, hooks: <commit-stage exit code>,
 *                prePush: <pre-push exit code>, gitleaks: <exit code>]
 */
def call(Map cfg = [:]) {
    Map opts = [
        reportDir              : 'slsec-reports',
        python                 : 'python3',
        preCommitVersion       : '4.3.0',
        gitleaks               : true,
        gitleaksVersion        : '8.30.1',
        gitleaksBaseUrl        : 'https://github.com/gitleaks/gitleaks/releases/download',
        failOnFindings         : true,
        // Fail when a scanner can't run (missing CLI or credentials, timeout, broken rules)
        // instead of warning. Exported as SLSEC_STRICT; overrides `strict:` in .slsec.yaml.
        strict                 : true,
        publish                : true,
        // `slsec doctor --ci` from this slsec release gates the run: the build's own
        // .pre-commit-config.yaml / .slsec.yaml can't switch the checks off. Set the
        // requirements here (in the Jenkinsfile, behind CODEOWNERS), not in the repo's config.
        slsecVersion           : '0.3.0',
        slsecSource            : 'https://github.com/kston83/shift-left-security',
        enforceSetup           : true,
        requireMode            : '',     // 'block' to fail while .slsec.yaml says warn
        requireProfiles        : '',     // e.g. 'terraform,python': their hooks must be present
        // Credential ids (Jenkins "Secret text"). null = skip the binding; a configured Snyk or
        // JFrog hook then fails (strict: true, the default) or warns (strict: false).
        snykTokenCredentialsId : null,
        jfrogUrlCredentialsId  : null,
        jfrogTokenCredentialsId: null,
    ] + cfg
    Map sonar = sonarOptions(cfg, opts)

    if (!isUnix()) {
        error('slsecScan needs a Linux or macOS agent (or a container on one).')
    }
    validateVersion('preCommitVersion', opts.preCommitVersion as String)
    validateVersion('gitleaksVersion', opts.gitleaksVersion as String)
    validateVersion('slsecVersion', opts.slsecVersion as String)
    if (!((opts.requireMode ?: '') as String in ['', 'warn', 'block'])) {
        error("slsecScan: requireMode must be 'warn', 'block' or empty, got '${opts.requireMode}'")
    }
    if (!(((opts.requireProfiles ?: '') as String) ==~ /[a-z,-]*/)) {
        error("slsecScan: requireProfiles must be a comma-separated list of profile names, got '${opts.requireProfiles}'")
    }

    String reportPath = "${env.WORKSPACE}/${opts.reportDir}"
    int hooksRc = 0
    int prePushRc = 0
    int gitleaksRc = 0
    int doctorRc = 0

    // Values go to the shell through environment variables, not Groovy string
    // interpolation, so nothing in `opts` can inject shell syntax.
    withEnv([
        "SLSEC_REPORT_DIR=${reportPath}",
        "SLSEC_CI=1",
        "SLSEC_STRICT=${opts.strict ? '1' : '0'}",
        "PRE_COMMIT_HOME=${env.WORKSPACE}/.slsec-cache/pre-commit",
        "SLSEC_PYTHON=${opts.python}",
        "SLSEC_PRE_COMMIT_VERSION=${opts.preCommitVersion}",
        "SLSEC_GITLEAKS_VERSION=${opts.gitleaksVersion}",
        "SLSEC_GITLEAKS_BASE_URL=${opts.gitleaksBaseUrl}",
        // one id per build, so pre-commit's file batches add up in one report and reports
        // left in a reused workspace by an earlier build are replaced, not merged
        "SLSEC_RUN_ID=${env.BUILD_TAG}",
        "SLSEC_VERSION=${opts.slsecVersion}",
        "SLSEC_SOURCE=${opts.slsecSource}",
        "SLSEC_REQUIRE_MODE=${opts.requireMode ?: ''}",
        "SLSEC_REQUIRE_PROFILES=${opts.requireProfiles ?: ''}",
    ]) {
        sh(label: 'slsec: install pre-commit', script: '''
            set -eu
            # stale reports from an earlier build in this workspace must not be published again
            rm -rf "$SLSEC_REPORT_DIR"
            mkdir -p "$SLSEC_REPORT_DIR"
            "$SLSEC_PYTHON" -m venv .slsec-cache/venv
            .slsec-cache/venv/bin/pip install --quiet --disable-pip-version-check "pre-commit==$SLSEC_PRE_COMMIT_VERSION"
        ''')

        // The build's own config files are input from the change under test; check them against
        // the policy in this library release and the options above.
        doctorRc = sh(label: 'slsec: doctor (setup gate)', returnStatus: true, script: '''
            set -u
            "$SLSEC_PYTHON" -m venv .slsec-cache/slsec-venv || exit 2
            .slsec-cache/slsec-venv/bin/pip install --quiet --disable-pip-version-check \
                "slsec @ git+${SLSEC_SOURCE}@v${SLSEC_VERSION}" || exit 2
            set -- doctor --ci
            [ -n "$SLSEC_REQUIRE_MODE" ] && set -- "$@" --require-mode "$SLSEC_REQUIRE_MODE"
            [ -n "$SLSEC_REQUIRE_PROFILES" ] && set -- "$@" --require-profiles "$SLSEC_REQUIRE_PROFILES"
            .slsec-cache/slsec-venv/bin/slsec "$@"
        ''')

        // Commit-stage hooks need no credentials, so none are bound here.
        hooksRc = sh(label: 'slsec: pre-commit hooks', returnStatus: true, script: '''
            .slsec-cache/venv/bin/pre-commit run --all-files --show-diff-on-failure --color=never --hook-stage pre-commit
        ''')

        // Pre-push stage = SCA (osv-scanner, Snyk, JFrog). Credentials are bound only here.
        withCredentials(credentialBindings(opts)) {
            prePushRc = sh(label: 'slsec: pre-push hooks (SCA)', returnStatus: true, script: '''
                .slsec-cache/venv/bin/pre-commit run --all-files --show-diff-on-failure --color=never --hook-stage pre-push
            ''')
        }

        if (opts.gitleaks) {
            gitleaksRc = sh(label: 'slsec: gitleaks (full history)', returnStatus: true, script: libraryResource('slsec/gitleaks-scan.sh'))
        }
    }

    if (opts.publish) {
        publishResults(opts.reportDir as String)
    }

    if (sonar.enabled) {
        sonarAnalysis(sonar)
    }

    if (doctorRc != 0) {
        String msg = 'slsec: the setup check failed (required hook missing or disabled, weak exception reason, or a requireMode/requireProfiles requirement); see the "slsec: doctor" step log'
        if (opts.enforceSetup) {
            error(msg)
        } else {
            unstable(msg)
        }
    }

    if (gitleaksRc == 1) {
        error('slsec: gitleaks found secrets in the git history. Rotate the credentials first, then clean up or allowlist. See docs/suppressions.md.')
    } else if (gitleaksRc != 0) {
        unstable("slsec: gitleaks could not run (exit ${gitleaksRc}); secrets were NOT scanned")
    }

    if (hooksRc != 0 || prePushRc != 0) {
        String msg = 'slsec: security hooks failed; see the "slsec: pre-commit hooks" and "slsec: pre-push hooks" step logs'
        if (opts.failOnFindings) {
            error(msg)
        } else {
            unstable(msg)
        }
    }
    return [doctor: doctorRc, hooks: hooksRc, prePush: prePushRc, gitleaks: gitleaksRc]
}

void validateVersion(String name, String value) {
    if (!(value ==~ /[0-9]+(\.[0-9]+)*/)) {
        error("slsecScan: ${name} must look like 1.2.3, got '${value}'")
    }
}

/** Secret-text bindings for whichever credential ids were supplied (others are skipped). */
List credentialBindings(Map opts) {
    List bindings = []
    if (opts.snykTokenCredentialsId) {
        bindings << string(credentialsId: opts.snykTokenCredentialsId as String, variable: 'SNYK_TOKEN')
    }
    if (opts.jfrogUrlCredentialsId) {
        bindings << string(credentialsId: opts.jfrogUrlCredentialsId as String, variable: 'JF_URL')
    }
    if (opts.jfrogTokenCredentialsId) {
        bindings << string(credentialsId: opts.jfrogTokenCredentialsId as String, variable: 'JF_ACCESS_TOKEN')
    }
    return bindings
}

/**
 * Normalise the sonar option. Accepts the map form
 * (sonar: [enabled: true, installation: 'SonarQube', command: '...']) or the 0.1.x form
 * (sonar: true, sonarServer: ..., sonarCommand: ...).
 */
Map sonarOptions(Map cfg, Map opts) {
    Map sonar = [
        enabled       : false,
        installation  : cfg.sonarServer ?: 'SonarQube',
        // e.g. 'sonar-scanner', './mvnw -B sonar:sonar', './gradlew sonar'
        command       : cfg.sonarCommand ?: 'sonar-scanner',
        timeoutMinutes: cfg.sonarTimeoutMinutes ?: 10,
        abortPipeline : null,
    ]
    if (cfg.sonar instanceof Map) {
        sonar = sonar + (cfg.sonar as Map)
    } else if (cfg.sonar) {
        sonar.enabled = true
    }
    if (sonar.abortPipeline == null) {
        sonar.abortPipeline = opts.failOnFindings
    }
    return sonar
}

void publishResults(String reportDir) {
    // slsecScan sets the build result itself, so the JUnit step must not mark it UNSTABLE.
    junit(testResults: "${reportDir}/*.xml", allowEmptyResults: true, skipMarkingBuildUnstable: true)
    // One Warnings NG tool id per scanner, only for reports that exist.
    List tools = [
        [file: 'checkov-terraform.sarif', id: 'slsec-checkov-terraform', name: 'slsec checkov (Terraform)'],
        [file: 'checkov-dockerfile.sarif', id: 'slsec-checkov-dockerfile', name: 'slsec checkov (Dockerfile)'],
        [file: 'slsec-sast.sarif', id: 'slsec-sast', name: 'slsec SAST'],
        [file: 'slsec-osv.sarif', id: 'slsec-osv', name: 'slsec osv-scanner (SCA)'],
        [file: 'slsec-snyk.sarif', id: 'slsec-snyk', name: 'slsec Snyk (SCA)'],
        [file: 'slsec-jfrog.sarif', id: 'slsec-jfrog', name: 'slsec JFrog (SCA)'],
        [file: 'gitleaks.sarif', id: 'slsec-gitleaks', name: 'slsec gitleaks'],
    ]
    try {
        for (Map tool : tools) {
            String path = "${reportDir}/${tool.file}"
            if (fileExists(path)) {
                recordIssues(
                    enabledForFailure: true,
                    tools: [sarif(pattern: path, id: tool.id as String, name: tool.name as String)]
                )
            }
        }
    } catch (NoSuchMethodError ignored) {
        echo 'slsec: Warnings Next Generation plugin not installed; SARIF archived but not visualised.'
    }
    archiveArtifacts(artifacts: "${reportDir}/**", allowEmptyArchive: true, fingerprint: false)
}

void sonarAnalysis(Map sonar) {
    withSonarQubeEnv(sonar.installation as String) {
        withEnv(["SLSEC_SONAR_COMMAND=${sonar.command}"]) {
            sh(label: 'slsec: SonarQube analysis', script: 'eval "$SLSEC_SONAR_COMMAND"')
        }
    }
    // Requires the SonarQube webhook pointing at <jenkins>/sonarqube-webhook/
    timeout(time: sonar.timeoutMinutes as int, unit: 'MINUTES') {
        waitForQualityGate(abortPipeline: sonar.abortPipeline as boolean)
    }
}
