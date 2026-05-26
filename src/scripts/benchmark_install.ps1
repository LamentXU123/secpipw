param(
    [string]$Package = "packaging==24.2",
    [int]$Runs = 6,
    [int]$Warmups = 1
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$benchRoot = Join-Path $repoRoot ".tmp-tests\benchmark-install"
$venvPath = Join-Path $benchRoot "venv"
$wheelhouse = Join-Path $benchRoot "wheelhouse"
$targets = Join-Path $benchRoot "targets"
$resultsDir = Join-Path $repoRoot ".tmp-tests\benchmark-results"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultPath = Join-Path $resultsDir "install-benchmark-$timestamp.json"

if (Test-Path $benchRoot) {
    Remove-Item -Recurse -Force $benchRoot
}

New-Item -ItemType Directory -Path $benchRoot | Out-Null
New-Item -ItemType Directory -Path $wheelhouse | Out-Null
New-Item -ItemType Directory -Path $targets | Out-Null
New-Item -ItemType Directory -Path $resultsDir | Out-Null

python -m venv $venvPath

$pythonExe = Join-Path $venvPath "Scripts\python.exe"
$pipExe = Join-Path $venvPath "Scripts\pip.exe"
$spipExe = Join-Path $venvPath "Scripts\spip.exe"

& $pythonExe -m pip install --disable-pip-version-check -q --upgrade pip | Out-Null
& $pythonExe -m pip install -q -e $repoRoot | Out-Null
& $pipExe download --disable-pip-version-check --no-deps --dest $wheelhouse $Package *> $null

if ($LASTEXITCODE -ne 0) {
    throw "failed to download benchmark package '$Package'"
}

$wheel = Get-ChildItem $wheelhouse -Filter *.whl | Select-Object -First 1
if (-not $wheel) {
    throw "benchmark wheel not found for '$Package'"
}

function Invoke-InstallRun {
    param(
        [string]$Label,
        [string]$Exe,
        [string[]]$Args,
        [int]$Index
    )

    $target = Join-Path $targets "$Label-$Index"
    if (Test-Path $target) {
        Remove-Item -Recurse -Force $target
    }

    $fullArgs = @()
    $fullArgs += $Args
    $fullArgs += @("--target", $target)

    $stdoutPath = Join-Path $targets "$Label-$Index.stdout.txt"
    $stderrPath = Join-Path $targets "$Label-$Index.stderr.txt"

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    & $Exe @fullArgs 1> $stdoutPath 2> $stderrPath
    $stopwatch.Stop()

    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Label run $Index failed with exit code $exitCode. stderr: $(Get-Content -Raw $stderrPath)"
    }

    [pscustomobject]@{
        label = $Label
        index = $Index
        duration_ms = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        target = $target
    }
}

$pipArgs = @(
    "install",
    "--disable-pip-version-check",
    "--no-input",
    "--no-index",
    "--find-links",
    $wheelhouse,
    $Package
)
$spipArgs = @(
    "install",
    "--no-index",
    "--find-links",
    $wheelhouse,
    $Package
)

for ($i = 1; $i -le $Warmups; $i++) {
    Invoke-InstallRun -Label "pip-warmup" -Exe $pipExe -Args $pipArgs -Index $i | Out-Null
    Invoke-InstallRun -Label "secured_pip-warmup" -Exe $spipExe -Args $spipArgs -Index $i | Out-Null
}

$pipRuns = @()
$securedPipRuns = @()

for ($i = 1; $i -le $Runs; $i++) {
    $pipRuns += Invoke-InstallRun -Label "pip" -Exe $pipExe -Args $pipArgs -Index $i
    $securedPipRuns += Invoke-InstallRun -Label "secured_pip" -Exe $spipExe -Args $spipArgs -Index $i
}

$pipAvg = [Math]::Round((($pipRuns.duration_ms | Measure-Object -Average).Average), 2)
$securedPipAvg = [Math]::Round((($securedPipRuns.duration_ms | Measure-Object -Average).Average), 2)
$deltaMs = [Math]::Round(($securedPipAvg - $pipAvg), 2)
$deltaPct = if ($pipAvg -eq 0) { 0 } else { [Math]::Round((($securedPipAvg - $pipAvg) / $pipAvg) * 100, 2) }

$result = [ordered]@{
    package = $Package
    wheel = $wheel.Name
    runs = $Runs
    warmups = $Warmups
    python = (& $pythonExe --version 2>&1)
    pip = (& $pipExe --version 2>&1)
    spip = (& $spipExe --version 2>&1)
    benchmark_root = $benchRoot
    pip_runs = $pipRuns
    secured_pip_runs = $securedPipRuns
    pip_avg_ms = $pipAvg
    secured_pip_avg_ms = $securedPipAvg
    delta_ms = $deltaMs
    delta_pct = $deltaPct
}

$result | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $resultPath
Get-Content -Raw -Encoding UTF8 $resultPath
