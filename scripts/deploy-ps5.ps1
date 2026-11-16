param(
    [Parameter(Mandatory = $true)][string]$TargetHost,
    [int]$FtpPort = 2121,
    [int]$PayloadPort = 9021,
    [switch]$SkipWww
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $RepoRoot "app\dist"
$ElfPath = Join-Path $RepoRoot "port-server\build\openbot-port-server.elf"

if (-not (Test-Path $ElfPath)) {
    throw "PS5 ELF not found at $ElfPath. Run scripts\build-ps5.ps1 first."
}

$wc = New-Object System.Net.WebClient
$ftpBase = "ftp://$TargetHost`:$FtpPort/data/openbot"

function Ensure-FtpDir([string]$url) {
    $parts = $url.Replace("ftp://$TargetHost`:$FtpPort", "").Trim('/').Split('/')
    $cur = "ftp://$TargetHost`:$FtpPort"
    foreach ($p in $parts) {
        if (-not $p) { continue }
        $cur = "$cur/$p"
        try {
            $req = [System.Net.FtpWebRequest]::Create($cur)
            $req.Method = [System.Net.WebRequestMethods+Ftp]::MakeDirectory
            $resp = $req.GetResponse()
            $resp.Close()
        } catch {
            # Already exists
        }
    }
}

Ensure-FtpDir "$ftpBase/www/assets"
Ensure-FtpDir "$ftpBase/workspaces"

if (-not $SkipWww) {
    if (-not (Test-Path $DistDir)) {
        throw "Frontend build directory not found at $DistDir. Run scripts\build-web-ps5.ps1 first."
    }
    $allFiles = Get-ChildItem -LiteralPath $DistDir -Recurse -File
    $woff2Stems = @{}
    foreach ($f in $allFiles) {
        if ($f.Extension -ieq ".woff2") {
            $dirKey = $f.DirectoryName.ToLowerInvariant()
            $stem = [System.IO.Path]::GetFileNameWithoutExtension($f.Name).ToLowerInvariant()
            $woff2Stems["$dirKey|$stem"] = $true
        }
    }
    $filesToUpload = $allFiles | Where-Object {
        $ext = $_.Extension.ToLowerInvariant()
        if ($ext -eq ".map") { return $false }
        if ($ext -eq ".ttf" -or $ext -eq ".woff") {
            $dirKey = $_.DirectoryName.ToLowerInvariant()
            $stem = [System.IO.Path]::GetFileNameWithoutExtension($_.Name).ToLowerInvariant()
            if ($woff2Stems.ContainsKey("$dirKey|$stem")) { return $false }
        }
        return $true
    }
    Write-Host "[deploy-ps5] Uploading $($filesToUpload.Count) web files to $ftpBase/www/ ..."
    $createdDirs = @{}
    $count = 0
    foreach ($f in $filesToUpload) {
        $rel = $f.FullName.Substring($DistDir.Length).TrimStart('\').Replace('\', '/')
        $remoteUrl = "$ftpBase/www/$rel"
        $remoteDir = Split-Path -Parent $rel
        if ($remoteDir) {
            $remoteDirNorm = $remoteDir.Replace('\', '/')
            if (-not $createdDirs.ContainsKey($remoteDirNorm)) {
                Ensure-FtpDir "$ftpBase/www/$remoteDirNorm"
                $createdDirs[$remoteDirNorm] = $true
            }
        }
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $req = [System.Net.FtpWebRequest]::Create($remoteUrl)
        $req.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
        $req.UseBinary = $true
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream()
        $s.Write($bytes, 0, $bytes.Length)
        $s.Close()
        $resp = $req.GetResponse()
        $resp.Close()
        $count++
        if ($count % 100 -eq 0) {
            Write-Host "[deploy-ps5] Uploaded $count / $($filesToUpload.Count)..."
        }
    }
    Write-Host "[deploy-ps5] Uploaded $count web files cleanly."
}

$MetaPath = Join-Path $RepoRoot "port-server\build\meta.json"
if (Test-Path $MetaPath) {
    $metaBytes = [System.IO.File]::ReadAllBytes($MetaPath)
    foreach ($metaDest in @("$ftpBase/meta.json", "ftp://$TargetHost`:$FtpPort/data/pldmgr/payloads/local/ps5-openbot/meta.json")) {
        try {
            if ($metaDest -like "*/data/pldmgr/*") {
                Ensure-FtpDir "ftp://$TargetHost`:$FtpPort/data/pldmgr/payloads/local/ps5-openbot"
            }
            $mreq = [System.Net.FtpWebRequest]::Create($metaDest)
            $mreq.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
            $mreq.UseBinary = $true
            $mreq.ContentLength = $metaBytes.Length
            $ms = $mreq.GetRequestStream()
            $ms.Write($metaBytes, 0, $metaBytes.Length)
            $ms.Close()
            $mresp = $mreq.GetResponse()
            $mresp.Close()
            Write-Host "[deploy-ps5] Uploaded meta.json -> $metaDest"
        } catch {
            Write-Host "[deploy-ps5] Note: skipped $metaDest ($($_.Exception.Message))"
        }
    }
}

$elfBytes = [System.IO.File]::ReadAllBytes($ElfPath)
$pldmgrElfDest = "ftp://$TargetHost`:$FtpPort/data/pldmgr/payloads/local/ps5-openbot/ps5-openbot.elf"
$oldPldmgrElf = "ftp://$TargetHost`:$FtpPort/data/pldmgr/payloads/local/ps5-openbot/openbot-port-server.elf"
try {
    Ensure-FtpDir "ftp://$TargetHost`:$FtpPort/data/pldmgr/payloads/local/ps5-openbot"
    $ereq = [System.Net.FtpWebRequest]::Create($pldmgrElfDest)
    $ereq.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
    $ereq.UseBinary = $true
    $ereq.ContentLength = $elfBytes.Length
    $es = $ereq.GetRequestStream()
    $es.Write($elfBytes, 0, $elfBytes.Length)
    $es.Close()
    $eresp = $ereq.GetResponse()
    $eresp.Close()
    Write-Host "[deploy-ps5] Synced ELF -> $pldmgrElfDest"
    try {
        $dreq = [System.Net.FtpWebRequest]::Create($oldPldmgrElf)
        $dreq.Method = [System.Net.WebRequestMethods+Ftp]::DeleteFile
        $dresp = $dreq.GetResponse()
        $dresp.Close()
    } catch {}
} catch {
    Write-Host "[deploy-ps5] Note: skipped $pldmgrElfDest ($($_.Exception.Message))"
}
Write-Host "[deploy-ps5] Sending $ElfPath ($($elfBytes.Length) bytes) to $TargetHost`:$PayloadPort ..."
$client = New-Object System.Net.Sockets.TcpClient($TargetHost, $PayloadPort)
$stream = $client.GetStream()
$stream.Write($elfBytes, 0, $elfBytes.Length)
$stream.Flush()
$stream.Close()
$client.Close()
Write-Host "[deploy-ps5] ELF sent! Open http://$TargetHost`:3010/ (setup token in /data/openbot/setup.token)"
