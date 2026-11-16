param(
    [string]$Sdk = $(if ($env:PS5_PAYLOAD_SDK) { $env:PS5_PAYLOAD_SDK } else { "E:\.ps5-toolchain\ps5-payload-sdk" }),
    [string]$LlvmBin = $(if ($env:PS5_LLVM_BIN) { $env:PS5_LLVM_BIN } else { "E:\.ps5-toolchain\llvm\LLVM\bin" }),
    [string]$TargetDir = $(Join-Path (Split-Path -Parent $PSScriptRoot) ".target-ps5")
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path $Sdk)) {
    throw "PS5_PAYLOAD_SDK not found at $Sdk"
}
if (-not (Test-Path $LlvmBin)) {
    throw "LLVM bin directory not found at $LlvmBin"
}

$env:PS5_PAYLOAD_SDK = $Sdk
$env:PS5_LLVM_BIN = $LlvmBin

$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
$SdkBin = Join-Path $Sdk "bin"
$PathParts = @()
if (Test-Path $CargoBin) { $PathParts += $CargoBin }
$PathParts += $LlvmBin
$PathParts += $SdkBin
$ExistingParts = ($env:PATH -split ';' | Where-Object { $_ })
$env:PATH = (($PathParts + $ExistingParts) | Select-Object -Unique) -join ';'

$ClangExe = Join-Path $LlvmBin "clang.exe"
$ArExe = Join-Path $SdkBin "llvm-ar.exe"
$StripExe = Join-Path $SdkBin "prospero-strip.exe"
$VerifyExe = Join-Path $SdkBin "elf-verify.exe"
$ReadelfExe = Join-Path $SdkBin "llvm-readelf.exe"
$LinkerCmd = Join-Path $RepoRoot "ps5-target\linker.cmd"
$TargetJson = Join-Path $RepoRoot "ps5-target\x86_64-sie-ps5-std.json"
$ShimHeader = (Join-Path $RepoRoot "ps5-target\include\ps5_sqlite_shim.h") -replace '\\', '/'
$SdkForward = $Sdk -replace '\\', '/'

foreach ($req in @($ClangExe, $ArExe, $StripExe, $VerifyExe, $ReadelfExe, $LinkerCmd, $TargetJson)) {
    if (-not (Test-Path $req)) {
        throw "Required build tool or config not found: $req"
    }
}

$env:CRATE_CC_NO_DEFAULTS = "1"
$env:CC_x86_64_sie_ps5_std = $ClangExe
$env:AR_x86_64_sie_ps5_std = $ArExe
$env:CFLAGS_x86_64_sie_ps5_std = "-target x86_64-sie-ps5 -isysroot $SdkForward -isystem $SdkForward/target/include -fno-stack-protector -fno-plt -femulated-tls -fPIC -O2 -include $ShimHeader -DSQLITE_OS_UNIX=1 -DSQLITE_THREADSAFE=1 -DSQLITE_TEMP_STORE=2 -DSQLITE_OMIT_LOAD_EXTENSION=1 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_MAX_MMAP_SIZE=0 -DHAVE_POSIX_FALLOCATE=0"
$env:CARGO_TARGET_X86_64_SIE_PS5_STD_LINKER = $LinkerCmd
$env:CARGO_TARGET_X86_64_SIE_PS5_STD_RUSTFLAGS = "-Zunstable-options --cfg mio_unsupported_force_waker_pipe"

Write-Host "[build-ps5] Building ps5-rt (release) for x86_64-sie-ps5-std..."
$RtArgs = @(
    "+nightly", "build", "--release", "--offline",
    "--manifest-path", (Join-Path $RepoRoot "ps5-rt\Cargo.toml"),
    "--target", $TargetJson,
    "--target-dir", $TargetDir,
    "-Z", "json-target-spec",
    "-Z", "build-std=std,panic_abort"
)
if (Test-Path (Join-Path $RepoRoot "ps5-rt\Cargo.lock")) {
    $RtArgs += "--locked"
}
& cargo @RtArgs
if ($LASTEXITCODE -ne 0) {
    throw "ps5-rt cargo build failed with exit code $LASTEXITCODE"
}

Write-Host "[build-ps5] Building openbot-port-server (release) for x86_64-sie-ps5-std..."
$ServerManifest = Join-Path $RepoRoot "port-server\Cargo.toml"
$ServerArgs = @(
    "+nightly", "build", "--release", "--locked", "--offline",
    "--manifest-path", $ServerManifest,
    "--target", $TargetJson,
    "--target-dir", $TargetDir,
    "-Z", "json-target-spec",
    "-Z", "build-std=std,panic_abort"
)
& cargo @ServerArgs
if ($LASTEXITCODE -ne 0) {
    throw "port-server cargo build failed with exit code $LASTEXITCODE"
}

$RawBin = Join-Path $TargetDir "x86_64-sie-ps5-std\release\openbot-port-server"
if (-not (Test-Path $RawBin)) {
    throw "Expected compiled binary not found at $RawBin"
}

$BuildDir = Join-Path $RepoRoot "port-server\build"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
$OutElf = Join-Path $BuildDir "openbot-port-server.elf"

Write-Host "[build-ps5] Stripping -> $OutElf"
& $StripExe -o $OutElf $RawBin
if ($LASTEXITCODE -ne 0) {
    throw "prospero-strip.exe failed with exit code $LASTEXITCODE"
}

Write-Host "[build-ps5] Verifying -> $OutElf"
& $VerifyExe $OutElf --require-sqlite-shim --unstripped $RawBin
if ($LASTEXITCODE -ne 0) {
    throw "elf-verify.exe failed with exit code $LASTEXITCODE"
}

Write-Host "[build-ps5] Inspecting ELF headers/dynamic -> $OutElf"
& $ReadelfExe -l -d $OutElf
if ($LASTEXITCODE -ne 0) {
    throw "llvm-readelf.exe failed with exit code $LASTEXITCODE"
}

$ElfSize = (Get-Item $OutElf).Length
$PlDmgElf = Join-Path $BuildDir "ps5-openbot.elf"
Copy-Item -LiteralPath $OutElf -Destination $PlDmgElf -Force

$ServerTomlPath = Join-Path $RepoRoot "port-server\Cargo.toml"
$CargoVersion = "0.1.0"
if (Test-Path $ServerTomlPath) {
    $VersionMatch = Select-String -Path $ServerTomlPath -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($VersionMatch) {
        $CargoVersion = $VersionMatch.Matches.Groups[1].Value
    }
}
$Checksum = (Get-FileHash -Algorithm SHA256 $PlDmgElf).Hash.ToLower()
$InstalledAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz") -replace '([+-]\d{2}):(\d{2})$', '$1$2'
$LastUpdate = (Get-Date).ToString("yyyy-MM-dd")
$MetaPath = Join-Path $BuildDir "meta.json"
$MetaJson = @"
{
  "schema": 2,
  "kind": "repo",
  "filename": "ps5-openbot.elf",
  "daemon": true,
  "autostart": true,
  "installed_at": "$InstalledAt",
  "id": "ps5-openbot",
  "source_url": "",
  "source_name": "Custom Build",
  "name": "OpenBot PS5",
  "version": "v$CargoVersion",
  "checksum": "$Checksum",
  "last_update": "$LastUpdate",
  "url": "",
  "source": "",
  "source_direct": "",
  "category": "Networking & Servers",
  "description": "Hosted OpenBot web application and PS5 daemon powered by PS5LM",
  "author": "",
  "details_url": ""
}
"@ -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($MetaPath, $MetaJson, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[build-ps5] Wrote $MetaPath (checksum: $Checksum)"

Write-Host "[build-ps5] SUCCESS: $OutElf ($ElfSize bytes)"
