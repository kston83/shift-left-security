/**
 * slsecScan: run the slsec shift-left security checks in Jenkins / CloudBees CI.
 *
 * Runs the same pre-commit hooks developers run locally (over all files) for both the
 * pre-commit stage and the pre-push stage (SCA), then a full-history gitleaks scan, and
 * publishes JUnit + SARIF results. Optionally runs a SonarQube analysis + quality gate.
 *
 *   @Library('slsec@v0.2.0') _
 *   pipeline {
 *     agent { label 'linux' }
 *     stages { stage('Security') { steps { slsecScan() } } }
 *   }
 *
 * Options (all optional): see vars/slsecScan.txt or docs/ci.md.
 * Returns a map: [hooks: <commit-stage exit code>, prePush: <pre-push exit code>, gitleaks: <exit code>]
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

    String reportPath = "${env.WORKSPACE}/${opts.reportDir}"
    int hooksRc = 0
    int prePushRc = 0
    int gitleaksRc = 0

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
    ]) {
        sh(label: 'slsec: install pre-commit', script: '''
            set -eu
            mkdir -p "$SLSEC_REPORT_DIR"
            "$SLSEC_PYTHON" -m venv .slsec-cache/venv
            .slsec-cache/venv/bin/pip install --quiet --disable-pip-version-check "pre-commit==$SLSEC_PRE_COMMIT_VERSION"
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
    return [hooks: hooksRc, prePush: prePushRc, gitleaks: gitleaksRc]
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
