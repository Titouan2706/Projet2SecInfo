$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.conda\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    Write-Error 'Conda environment not found. Run scripts\setup.ps1 first.'
    exit 1
}

& $python (Join-Path $root 'main.py') @args
exit $LASTEXITCODE
