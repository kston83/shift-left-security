<#
.SYNOPSIS
  Add slsec shift-left security hooks to the current git repo (Windows).

.EXAMPLE
  .\install.ps1
  .\install.ps1 --profile terraform,docker --mode block

.NOTES
  Environment overrides: SLSEC_SOURCE_URL (git URL of this repo), SLSEC_REV (tag).
  Prefers uv, then pipx, then the py launcher / python with pip --user.
  Works in Windows PowerShell 5.1 and PowerShell 7.
#>
$ErrorActionPreference = 'Stop'

$source = if ($env:SLSEC_SOURCE_URL) { $env:SLSEC_SOURCE_URL } else { 'https://github.com/kston83/shift-left-security' }
$rev = if ($env:SLSEC_REV) { $env:SLSEC_REV } else { 'v0.2.0' }
$spec = "git+$source@$rev"
$initArgs = @('init', '--source-url', $source, '--rev', $rev) + $args

function Test-Command($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

git rev-parse --show-toplevel *> $null
if ($LASTEXITCODE -ne 0) { Write-Error 'slsec: run this from inside a git repository'; exit 2 }

if (Test-Command 'uv') {
    if (-not (Test-Command 'pre-commit')) { uv tool install pre-commit }
    & uvx --from $spec slsec @initArgs
}
elseif (Test-Command 'pipx') {
    if (-not (Test-Command 'pre-commit')) { pipx install pre-commit }
    & pipx run --spec $spec slsec @initArgs
}
else {
    $py = $null
    if (Test-Command 'py') { $py = @('py', '-3') }
    elseif (Test-Command 'python') { $py = @('python') }
    if (-not $py) { Write-Error 'slsec: need Python 3.9+ (or uv / pipx) on PATH'; exit 2 }
    $exe = $py[0]; $pre = @($py | Select-Object -Skip 1)
    & $exe @pre -m pip install --user --quiet --disable-pip-version-check pre-commit $spec
    & $exe @pre -m slsec @initArgs
}
exit $LASTEXITCODE
