$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$environment = Join-Path $root '.conda'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\Miniconda3'
$conda = Get-Command conda.exe -ErrorAction SilentlyContinue

if ($conda) {
    $condaPath = $conda.Source
} else {
    $candidates = @(
        (Join-Path $installDir 'Scripts\conda.exe')
        (Join-Path $HOME 'miniconda3\Scripts\conda.exe')
        (Join-Path $HOME 'anaconda3\Scripts\conda.exe')
    )
    $condaPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $condaPath) {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            throw 'winget is required to install Miniconda.'
        }
        $condaPath = Join-Path $installDir 'Scripts\conda.exe'
        & winget.exe install --id Anaconda.Miniconda3 --exact --silent --scope user `
            --location $installDir --accept-package-agreements --accept-source-agreements `
            --disable-interactivity
        if ($LASTEXITCODE -ne 0) {
            throw "Miniconda installation failed (winget exit code $LASTEXITCODE)."
        }
        if (-not (Test-Path -LiteralPath $condaPath)) {
            throw "Miniconda was not found at $condaPath. Add conda to PATH and rerun setup."
        }
    }
}

$history = Join-Path $environment 'conda-meta\history'
if (-not (Test-Path -LiteralPath $history)) {
    if (Test-Path -LiteralPath $environment) {
        throw "$environment already exists but is not a conda environment."
    }
    & $condaPath create --yes --prefix $environment --override-channels `
        --channel conda-forge python=3.12 pip
    if ($LASTEXITCODE -ne 0) {
        throw "Conda environment creation failed (exit code $LASTEXITCODE)."
    }
}

& $condaPath run --no-capture-output --prefix $environment python -m pip install `
    -r (Join-Path $root 'requirements.txt')
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed (exit code $LASTEXITCODE)."
}

Write-Host "Setup complete. Run: powershell -ExecutionPolicy Bypass -File scripts\run.ps1"
