<#
.SYNOPSIS
    Fresh, network-resilient run of the full corpus pipeline.

.DESCRIPTION
    1. Fresh start: wipes data/ and the resume state (completed-sources ledger +
       dedup checkpoints) so the build begins from a clean slate.
    2. Runs `cybersec-slm all --resume` in a loop. Because completed sources are
       recorded in logs/completed_sources.txt, each pass skips what already
       finished and only (re)attempts pending or previously-failed sources. So if
       the network drops mid-run, the process exits and the next pass picks up
       exactly where it left off — no source is re-downloaded.
    3. Stops when a full pass adds no newly-completed sources (converged) or after
       -MaxPasses passes, then reports whether data/final/dataset.jsonl was built.

.NOTES
    Requires the stuck/previous pipeline (if any) to be stopped first, otherwise
    the data/ wipe fails on locked files. Run:
      Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -match 'cybersec-slm\.exe"?\s+all' -or $_.CommandLine -match '--multiprocessing-fork' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
#>
param(
    [int]$MaxPasses = 20,
    [int]$SleepSeconds = 30,
    [double]$SourceTimeout = 1800
)

$ErrorActionPreference = 'Continue'
$repo   = Split-Path -Parent $PSScriptRoot          # tools/ -> repo root
$cli    = Join-Path $repo '.venv\Scripts\cybersec-slm.exe'
$logs   = Join-Path $repo 'logs'
$ledger = Join-Path $logs 'completed_sources.txt'
$data   = Join-Path $repo 'data'
$dataset = Join-Path $repo 'data\final\dataset.jsonl'

Write-Host "=== fresh start: wiping data/ and resume state ==="
if (Test-Path $data) {
    Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
    if (Test-Path $data) {
        Write-Host "ERROR: could not remove $data (files still locked?). Stop any running pipeline first." -ForegroundColor Red
        exit 1
    }
}
foreach ($f in @('completed_sources.txt', 'dedup_checkpoint.json', 'dedup_done.json')) {
    $p = Join-Path $logs $f
    if (Test-Path $p) { Remove-Item -Force $p -ErrorAction SilentlyContinue }
}

$prev = -1
for ($i = 1; $i -le $MaxPasses; $i++) {
    Write-Host ""
    Write-Host "=== pipeline pass $i / $MaxPasses  ($(Get-Date -Format o)) ==="
    & $cli all --resume --source-timeout $SourceTimeout
    $exit = $LASTEXITCODE

    $count = if (Test-Path $ledger) { (Get-Content $ledger | Where-Object { $_.Trim() }).Count } else { 0 }
    Write-Host "pass $i finished (exit=$exit); completed sources so far: $count"

    if ($count -eq $prev) {
        Write-Host "no new sources completed this pass -> converged; stopping."
        break
    }
    $prev = $count
    Write-Host "sleeping $SleepSeconds s before the next resume pass (lets a dropped network recover)..."
    Start-Sleep -Seconds $SleepSeconds
}

Write-Host ""
Write-Host "=== supervisor finished ==="
if (Test-Path $dataset) {
    $lines = (Get-Content $dataset | Measure-Object -Line).Lines
    Write-Host "final dataset: $dataset  ($lines records)" -ForegroundColor Green
} else {
    Write-Host "WARNING: no final dataset produced. Either the EDA sufficiency gate blocked normalization, or every source failed (check the log above)." -ForegroundColor Yellow
}
