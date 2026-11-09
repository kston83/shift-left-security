/**
 * slsecScan: run the slsec shift-left security checks in Jenkins / CloudBees CI.
 *
 * Runs the same pre-commit hooks developers run locally (over all files), then a
 * full-history gitleaks scan, and publishes JUnit + SARIF results.
 *
 *   @Library('slsec@v0.1.0') _
 *   pipeline {
 *     agent { label 'linux' }
 *     stages { stage('Security') { steps { slsecScan() } } }
 *   }
 *
 * Options (all optional): see vars/slsecScan.txt or docs/ci.md.
 * Returns a map: [hooks: <exit code>, gitleaks: <exit code>]
 */
def call(Map cfg = [:]) {
    Map opts = [
        reportDir         : 'slsec-reports',
        python            : 'python3',
        preCommitVersion  : '4.3.0',
        gitleaks          : true,
        gitleaksVersion   : '8.30.1',
        gitleaksBaseUrl   : 'https://github.com/gitleaks/gitleaks/releases/download',
        failOnFindings    : true,
        publish           : true,
        sonar             : false,
        sonarServer       : 'SonarQube',
        sonarCommand      : 'sonar-scanner',
        sonarTimeoutMinutes: 10,
    ] + cfg

    if (!isUnix()) {
        error('slsecScan needs a Linux or macOS agent (or a container on one).')
    }
    validateVersion('preCommitVersion', opts.preCommitVersion as String)
    validateVersion('gitleaksVersion', opts.gitleaksVersion as String)

    String reportPath = "${env.WORKSPACE}/${opts.reportDir}"
    int hooksRc = 0
    int gitleaksRc = 0

    // Values go to the shell through environment variables, not Groovy string
    // interpolation, so nothing in `opts` can inject shell syntax.
    withEnv([
        "SLSEC_REPORT_DIR=${reportPath}",
        "SLSEC_CI=1",
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

        hooksRc = sh(label: 'slsec: pre-commit hooks', returnStatus: true, script: '''
            .slsec-cache/venv/bin/pre-commit run --all-files --show-diff-on-failure --color=never
        ''')

        if (opts.gitleaks) {
            gitleaksRc = sh(label: 'slsec: gitleaks (full history)', returnStatus: true, script: libraryResource('slsec/gitleaks-scan.sh'))
        }
    }

    if (opts.publish) {
        publishResults(opts.reportDir as String)
    }

    if (opts.sonar) {
        sonarAnalysis(opts)
    }

    if (gitleaksRc == 1) {
        error('slsec: gitleaks found secrets in the git history. Rotate the credentials first, then clean up or allowlist. See docs/suppressions.md.')
    } else if (gitleaksRc != 0) {
        unstable("slsec: gitleaks could not run (exit ${gitleaksRc}); secrets were NOT scanned")
    }

    if (hooksRc != 0) {
        String msg = 'slsec: security hooks failed; see the "slsec: pre-commit hooks" step log'
        if (opts.failOnFindings) {
            error(msg)
        } else {
            unstable(msg)
        }
    }
    return [hooks: hooksRc, gitleaks: gitleaksRc]
}

void validateVersion(String name, String value) {
    if (!(value ==~ /[0-9]+(\.[0-9]+)*/)) {
        error("slsecScan: ${name} must look like 1.2.3, got '${value}'")
    }
}

void publishResults(String reportDir) {
    // slsecScan sets the build result itself, so the JUnit step must not mark it UNSTABLE.
    junit(testResults: "${reportDir}/*.xml", allowEmptyResults: true, skipMarkingBuildUnstable: true)
    try {
        recordIssues(
            enabledForFailure: true,
            tools: [sarif(pattern: "${reportDir}/*.sarif", id: 'slsec', name: 'slsec security')]
        )
    } catch (NoSuchMethodError ignored) {
        echo 'slsec: Warnings Next Generation plugin not installed; SARIF archived but not visualised.'
    }
    archiveArtifacts(artifacts: "${reportDir}/**", allowEmptyArchive: true, fingerprint: false)
}

void sonarAnalysis(Map opts) {
    withSonarQubeEnv(opts.sonarServer as String) {
        withEnv(["SLSEC_SONAR_COMMAND=${opts.sonarCommand}"]) {
            // e.g. 'sonar-scanner', './mvnw -B sonar:sonar', './gradlew sonar'
            sh(label: 'slsec: SonarQube analysis', script: 'eval "$SLSEC_SONAR_COMMAND"')
        }
    }
    // Requires the SonarQube webhook pointing at <jenkins>/sonarqube-webhook/
    timeout(time: opts.sonarTimeoutMinutes as int, unit: 'MINUTES') {
        waitForQualityGate(abortPipeline: opts.failOnFindings as boolean)
    }
}
