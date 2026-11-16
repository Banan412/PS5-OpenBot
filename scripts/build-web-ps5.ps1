$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bun = Join-Path $root '.tools\node_modules\bun\bin\bun.exe'
if (-not (Test-Path -LiteralPath $bun)) {
    throw 'Bun 1.4.3 is missing. Run npm install --prefix .tools --no-save --no-package-lock bun@1.4.3 from the repository root.'
}
if ((& $bun --version).Trim() -ne '1.4.3') { throw 'Expected Bun 1.4.3.' }
$oldPath = $env:PATH
$oldTenant = $env:TENANT_PACKAGE_DIR
try {
    $env:PATH = "$(Split-Path -Parent $bun);$oldPath"
    $env:TENANT_PACKAGE_DIR = Join-Path $root 'ps5-brand'
    Push-Location $root
    try {
        & $bun install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
        & $bun run --filter app build
        if ($LASTEXITCODE -ne 0) { throw 'Web build failed.' }
        Write-Host "Website built at $(Join-Path $root 'app\dist')"
    } finally { Pop-Location }
} finally {
    $env:PATH = $oldPath
    $env:TENANT_PACKAGE_DIR = $oldTenant
}
