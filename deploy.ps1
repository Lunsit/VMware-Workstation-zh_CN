#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Elevated,
    [string]$JobFile,
    [string]$ResultFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptRoot)) { $ScriptRoot = (Get-Location).Path }
$script:LogFile = $null

function Write-Title {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor DarkCyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 62) -ForegroundColor DarkCyan
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default)
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = Read-Host "$Prompt $suffix"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        switch ($answer.Trim().ToLowerInvariant()) {
            'y' { return $true }
            'yes' { return $true }
            'n' { return $false }
            'no' { return $false }
            default { Write-Host '请输入 y 或 n。' -ForegroundColor Yellow }
        }
    }
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-PEMachine {
    param([string]$Path)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -le 0 -or $peOffset -gt ($stream.Length - 6)) { throw "无效的 PE 文件: $Path" }
        $stream.Position = $peOffset + 4
        return [int]$reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

function Get-ArchName {
    param([int]$Machine)
    switch ($Machine) {
        0x014C { return 'x86' }
        0x8664 { return 'x64' }
        0xAA64 { return 'ARM64' }
        default { return ('0x{0:X4}' -f $Machine) }
    }
}

function Test-VmwareInstallPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($Path.Trim().Trim('"')) } catch { return $false }
    return (Test-Path -LiteralPath (Join-Path $full 'vmware.exe') -PathType Leaf)
}

function Get-VmwareInfo {
    param([string]$Path)
    if (-not (Test-VmwareInstallPath $Path)) { return $null }
    $full = ([System.IO.Path]::GetFullPath($Path.Trim().Trim('"')))
    $full = $full.TrimEnd('\')
    $exe = Join-Path $full 'vmware.exe'
    $item = Get-Item -LiteralPath $exe
    $version = [string]$item.VersionInfo.ProductVersion
    $major = 0
    if ($version -match '^(\d+)') { $major = [int]$Matches[1] }
    return [pscustomobject]@{
        Path    = $full
        Version = $version
        Major   = $major
        Machine = [int](Get-PEMachine $exe)
    }
}

function Get-PropValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-InstallCandidates {
    $raw = New-Object System.Collections.Generic.List[string]
    foreach ($keyPath in @(
        'HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation',
        'HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation'
    )) {
        try {
            $props = Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop
            $value = Get-PropValue $props 'InstallPath'
            if ($value) { $raw.Add([string]$value) }
        } catch { }
    }
    foreach ($appPath in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\vmware.exe',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\vmware.exe'
    )) {
        try {
            $key = Get-Item -LiteralPath $appPath -ErrorAction Stop
            $default = [string]$key.GetValue('')
            if ($default) { $raw.Add((Split-Path -Parent $default)) }
        } catch { }
    }
    foreach ($uninstallRoot in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )) {
        try {
            foreach ($sub in @(Get-ChildItem -LiteralPath $uninstallRoot -ErrorAction Stop)) {
                try {
                    $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop
                    $name = [string](Get-PropValue $props 'DisplayName')
                    $loc = [string](Get-PropValue $props 'InstallLocation')
                    if ($name -like 'VMware Workstation*' -and $loc) { $raw.Add($loc) }
                } catch { }
            }
        } catch { }
    }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base) { $raw.Add((Join-Path $base 'VMware\VMware Workstation')) }
    }

    $list = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($candidate in $raw) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $trimmed = $candidate.Trim().Trim('"').TrimEnd('\')
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if (-not $seen.ContainsKey($trimmed)) {
            $seen[$trimmed] = $true
            $list.Add($trimmed)
        }
    }
    return $list.ToArray()
}

function Select-InstallPath {
    $infos = @()
    foreach ($candidate in @(Get-InstallCandidates)) {
        $info = Get-VmwareInfo $candidate
        if ($info) {
            $duplicate = $false
            foreach ($existing in $infos) {
                if ($existing.Path -eq $info.Path) { $duplicate = $true }
            }
            if (-not $duplicate) { $infos += $info }
        }
    }
    if ($infos.Count -eq 1) {
        Write-Host "已自动检测到安装目录: $($infos[0].Path)" -ForegroundColor Green
        return $infos[0]
    }
    if ($infos.Count -gt 1) {
        Write-Host '检测到多个 VMware Workstation 安装：' -ForegroundColor Yellow
        for ($i = 0; $i -lt $infos.Count; $i++) {
            Write-Host ('  [{0}] {1}  ({2}, {3})' -f ($i + 1), $infos[$i].Path, $infos[$i].Version, (Get-ArchName $infos[$i].Machine))
        }
        while ($true) {
            $answer = Read-Host "请选择安装目录 [1-$($infos.Count)]"
            $index = 0
            if ([int]::TryParse($answer, [ref]$index) -and $index -ge 1 -and $index -le $infos.Count) {
                return $infos[$index - 1]
            }
            Write-Host '输入无效，请重试。' -ForegroundColor Yellow
        }
    }
    Write-Host '未能自动检测到 VMware Workstation 安装目录。' -ForegroundColor Yellow
    while ($true) {
        $entered = Read-Host '请输入 VMware Workstation 安装目录（包含 vmware.exe），输入 q 退出'
        if ($entered -match '^\s*q\s*$') { return $null }
        $info = Get-VmwareInfo $entered
        if ($info) { return $info }
        Write-Host '该目录中未找到 vmware.exe，请检查后重试。' -ForegroundColor Yellow
    }
}

function Read-InstallPathFromUser {
    while ($true) {
        $entered = Read-Host '请输入 VMware Workstation 安装目录（包含 vmware.exe），输入 q 退出'
        if ($entered -match '^\s*q\s*$') { return $null }
        if (Test-VmwareInstallPath $entered) {
            return ([System.IO.Path]::GetFullPath($entered.Trim().Trim('"'))).TrimEnd('\')
        }
        Write-Host '该目录中未找到 vmware.exe，请检查后重试。' -ForegroundColor Yellow
    }
}

function Get-PackageList {
    $items = @(
        [pscustomobject]@{
            Id = '17'; Folder = '17-official-zh_CN'; Title = '17 原版汉化'
            Description = '官方 17.6.4 简体中文资源（x86）'
            ExpectMajor = 17; BuildHint = '24832109'; TrayDefault = $false
            Machine = 0; Available = $false; Status = ''
        },
        [pscustomobject]@{
            Id = 'full'; Folder = 'full-zh_CN'; Title = '全汉化'
            Description = '26H1u1 完整汉化（x64，含托盘补丁）'
            ExpectMajor = 26; BuildHint = '25688693'; TrayDefault = $true
            Machine = 0; Available = $false; Status = ''
        }
    )
    foreach ($item in $items) {
        $dir = Join-Path $ScriptRoot $item.Folder
        $required = @('vmui-zh_CN.dll', 'vmappsdk-zh_CN.dll', 'vmware.vmsg')
        $missing = @()
        foreach ($name in $required) {
            if (-not (Test-Path -LiteralPath (Join-Path $dir $name) -PathType Leaf)) { $missing += $name }
        }
        if ($missing.Count -gt 0) {
            $item.Status = '包文件缺失: ' + ($missing -join ', ')
            continue
        }
        try {
            $item.Machine = [int](Get-PEMachine (Join-Path $dir 'vmui-zh_CN.dll'))
            $item.Available = $true
        } catch {
            $item.Status = '无法读取资源 DLL: ' + $_.Exception.Message
        }
    }
    return $items
}

function Get-PrefEncoding {
    try { return [System.Text.Encoding]::GetEncoding(936) }
    catch { return [System.Text.Encoding]::Default }
}

function Resolve-InstallChildPath {
    param([string]$InstallPath, [string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath)) { throw '文件记录无效。' }
    if ([System.IO.Path]::IsPathRooted($RelativePath)) { throw '文件记录包含绝对路径，已拒绝。' }
    $root = [System.IO.Path]::GetFullPath($InstallPath).TrimEnd('\')
    $full = [System.IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    if (-not $full.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "文件路径越界: $RelativePath"
    }
    return $full
}

function Write-ElevatedResult {
    param([string]$Path, [bool]$Ok, [string]$Message, [hashtable]$Data)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $obj = [ordered]@{
        success     = $Ok
        message     = $Message
        data        = $Data
        completedAt = (Get-Date).ToString('o')
    }
    try {
        $json = $obj | ConvertTo-Json -Depth 10
        Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    } catch { }
}

function Invoke-ElevatedChild {
    param([hashtable]$Job)
    $publicDir = $env:PUBLIC
    if ([string]::IsNullOrWhiteSpace($publicDir) -or -not (Test-Path -LiteralPath $publicDir)) {
        $publicDir = [System.IO.Path]::GetTempPath()
    }
    $id = [guid]::NewGuid().ToString('N')
    $jobPath = Join-Path $publicDir "vmware-zhdeploy-$id.json"
    $resultPath = Join-Path $publicDir "vmware-zhdeploy-$id.result.json"
    try {
        ($Job | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $jobPath -Encoding UTF8
        $argList = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $PSCommandPath),
            '-Elevated',
            '-JobFile', ('"{0}"' -f $jobPath),
            '-ResultFile', ('"{0}"' -f $resultPath)
        )
        Write-Host '正在请求管理员权限，请在 UAC 窗口中选择“是”...' -ForegroundColor Cyan
        try {
            $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -Wait -PassThru -ErrorAction Stop
        } catch {
            return [pscustomobject]@{ Canceled = $true; ExitCode = -1; Result = $null; Error = $_.Exception.Message }
        }
        $result = $null
        if (Test-Path -LiteralPath $resultPath) {
            try {
                $result = (Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8) | ConvertFrom-Json
            } catch { $result = $null }
        }
        return [pscustomobject]@{ Canceled = $false; ExitCode = $proc.ExitCode; Result = $result; Error = $null }
    } finally {
        foreach ($file in @($jobPath, $resultPath)) {
            try { if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force } } catch { }
        }
    }
}

function Start-TrayIfNeeded {
    param([string]$InstallPath)
    if (Get-Process -Name vmware-tray -ErrorAction SilentlyContinue) { return }
    $tray = Join-Path $InstallPath 'vmware-tray.exe'
    if (-not (Test-Path -LiteralPath $tray -PathType Leaf)) { return }
    try {
        Start-Process -FilePath $tray | Out-Null
        Write-Host '已启动托盘程序。' -ForegroundColor Green
    } catch {
        Write-Host "托盘程序未能自动启动，请登录后手动运行: $tray" -ForegroundColor Yellow
    }
}

function Invoke-Rollback {
    param($Manifest, [string]$BackupDir, [string]$InstallPath)
    Write-Log '开始自动回滚...' 'WARN'
    if ([bool]$Manifest['replaceTray']) {
        Get-Process -Name vmware-tray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
    foreach ($entry in @($Manifest['files'])) {
        $target = Resolve-InstallChildPath -InstallPath $InstallPath -RelativePath ([string]$entry['target'])
        if ([bool]$entry['existed']) {
            $backupRel = [string]$entry['backup']
            if ([string]::IsNullOrWhiteSpace($backupRel)) { throw "备份记录缺失: $($entry['target'])" }
            $backupPath = Join-Path $BackupDir $backupRel
            if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) { throw "备份文件缺失: $backupRel" }
            Copy-Item -LiteralPath $backupPath -Destination $target -Force
        } elseif (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Force
        }
    }
    if ([bool]$Manifest['replaceTray']) {
        $tray = $Manifest['tray']
        if ($tray) {
            $target = Resolve-InstallChildPath -InstallPath $InstallPath -RelativePath 'vmware-tray.exe'
            if ([bool]$tray['existed']) {
                $backupPath = Join-Path $BackupDir ([string]$tray['backup'])
                if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) { throw '托盘程序备份缺失。' }
                Copy-Item -LiteralPath $backupPath -Destination $target -Force
            } elseif (Test-Path -LiteralPath $target) {
                Remove-Item -LiteralPath $target -Force
            }
        }
    }
    $pref = $Manifest['preferences']
    if ($pref -and $pref['path']) {
        $prefPath = [string]$pref['path']
        if ([bool]$pref['localeExisted'] -and -not [string]::IsNullOrWhiteSpace([string]$pref['previousLocale'])) {
            Set-PrefLocale -Path $prefPath -Locale ([string]$pref['previousLocale']) -Encoding (Get-PrefEncoding)
        } else {
            Remove-PrefLocale -Path $prefPath -Encoding (Get-PrefEncoding)
        }
        if (-not [bool]$pref['existed'] -and (Test-Path -LiteralPath $prefPath)) {
            if ([string]::IsNullOrWhiteSpace([System.IO.File]::ReadAllText($prefPath, (Get-PrefEncoding)))) {
                Remove-Item -LiteralPath $prefPath -Force
            }
        }
    }
    if (-not [bool]$Manifest['messagesDirExisted']) {
        $messageDir = Join-Path $InstallPath 'messages\zh_CN'
        if ((Test-Path -LiteralPath $messageDir) -and @(Get-ChildItem -LiteralPath $messageDir -Force).Count -eq 0) {
            Remove-Item -LiteralPath $messageDir -Force
        }
    }
    Write-Log '回滚完成。' 'WARN'
}

function Set-PrefLocale {
    param([string]$Path, [string]$Locale, [System.Text.Encoding]$Encoding)
    $text = ''
    if (Test-Path -LiteralPath $Path) { $text = [System.IO.File]::ReadAllText($Path, $Encoding) }
    $newLine = if ($text.Contains("`r`n")) { "`r`n" } elseif ($text.Contains("`n")) { "`n" } else { "`r`n" }
    $line = 'pref.locale = "' + $Locale + '"'
    $pattern = '(?m)^[ \t]*pref\.locale[ \t]*=[^\r\n]*'
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] { param($match) return $line }
    if ([System.Text.RegularExpressions.Regex]::IsMatch($text, $pattern)) {
        $text = [System.Text.RegularExpressions.Regex]::Replace($text, $pattern, $evaluator)
    } else {
        if ($text.Length -gt 0 -and -not ($text.EndsWith("`r`n") -or $text.EndsWith("`n"))) { $text += $newLine }
        $text += $line + $newLine
    }
    $dir = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $text, $Encoding)
}

function Remove-PrefLocale {
    param([string]$Path, [System.Text.Encoding]$Encoding)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $text = [System.IO.File]::ReadAllText($Path, $Encoding)
    $newText = [System.Text.RegularExpressions.Regex]::Replace($text, '(?m)^[ \t]*pref\.locale[ \t]*=[^\r\n]*(?:\r?\n)?', '')
    [System.IO.File]::WriteAllText($Path, $newText, $Encoding)
}

function Get-PrefLocaleInfo {
    param([string]$Path, [System.Text.Encoding]$Encoding)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Exists = $false; LocaleExisted = $false; PreviousLocale = $null }
    }
    $text = [System.IO.File]::ReadAllText($Path, $Encoding)
    $match = [System.Text.RegularExpressions.Regex]::Match($text, '(?m)^[ \t]*pref\.locale[ \t]*=([^\r\n]*)')
    $value = $null
    if ($match.Success) { $value = $match.Groups[1].Value.Trim().Trim('"').Trim() }
    return [pscustomobject]@{ Exists = $true; LocaleExisted = $match.Success; PreviousLocale = $value }
}

function Invoke-ElevatedDeploy {
    param([string]$JobPath, [string]$ResultPath)
    $job = (Get-Content -LiteralPath $JobPath -Raw -Encoding UTF8) | ConvertFrom-Json
    $install = ([string]$job.installPath).TrimEnd('\')
    if (-not (Test-VmwareInstallPath $install)) { throw "安装目录无效或其中没有 vmware.exe: $install" }
    $install = ([System.IO.Path]::GetFullPath($install)).TrimEnd('\')

    $packageFolder = [string]$job.packageFolder
    $packageDir = [System.IO.Path]::GetFullPath((Join-Path $ScriptRoot $packageFolder))
    $rootPrefix = $ScriptRoot.TrimEnd('\') + '\'
    if (-not $packageDir.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw '汉化包路径无效。'
    }

    $requiredNames = @('vmui-zh_CN.dll', 'vmappsdk-zh_CN.dll', 'vmware.vmsg')
    foreach ($name in $requiredNames) {
        if (-not (Test-Path -LiteralPath (Join-Path $packageDir $name) -PathType Leaf)) {
            throw "汉化包缺少文件: $name"
        }
    }

    $appMachine = [int](Get-PEMachine (Join-Path $install 'vmware.exe'))
    $packageMachine = [int](Get-PEMachine (Join-Path $packageDir 'vmui-zh_CN.dll'))
    if ($appMachine -ne $packageMachine) {
        throw ('汉化包架构 {0} 与已安装程序架构 {1} 不一致，已拒绝部署。' -f (Get-ArchName $packageMachine), (Get-ArchName $appMachine))
    }

    $replaceTray = [bool]$job.replaceTray
    $traySource = Join-Path $packageDir 'vmware-tray.exe'
    if ($replaceTray) {
        if (-not (Test-Path -LiteralPath $traySource -PathType Leaf)) { throw '汉化包中缺少托盘程序 vmware-tray.exe。' }
        $trayTarget = Join-Path $install 'vmware-tray.exe'
        if (Test-Path -LiteralPath $trayTarget -PathType Leaf) {
            if ([int](Get-PEMachine $trayTarget) -ne [int](Get-PEMachine $traySource)) {
                throw '托盘程序架构不一致，已拒绝替换。'
            }
        }
    }

    $closeVmware = [bool]$job.closeVmware
    $running = @(Get-Process -Name vmware -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0 -and -not $closeVmware) {
        throw 'VMware Workstation 正在运行，请关闭后重试。'
    }

    $prefsDir = [string]$job.userAppData
    if ([string]::IsNullOrWhiteSpace($prefsDir) -or -not [System.IO.Path]::IsPathRooted($prefsDir)) {
        throw '无法确定当前用户的 AppData 目录。'
    }
    $prefsPath = Join-Path $prefsDir 'VMware\preferences.ini'
    $prefsEncoding = Get-PrefEncoding

    $messageDir = Join-Path $install 'messages\zh_CN'
    $messagesDirExisted = Test-Path -LiteralPath $messageDir

    $backupRoot = Join-Path $ScriptRoot 'backup'
    if (-not (Test-Path -LiteralPath $backupRoot)) { New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupDir = Join-Path $backupRoot $stamp
    $counter = 1
    while (Test-Path -LiteralPath $backupDir) {
        $backupDir = Join-Path $backupRoot ('{0}-{1}' -f $stamp, $counter)
        $counter++
    }
    $backupFilesDir = Join-Path $backupDir 'files'
    New-Item -ItemType Directory -Path $backupFilesDir -Force | Out-Null
    $script:LogFile = Join-Path $backupDir 'deploy.log'

    $appVersion = [string](Get-Item -LiteralPath (Join-Path $install 'vmware.exe')).VersionInfo.ProductVersion
    Write-Log "安装目录: $install"
    Write-Log "已安装版本: $appVersion ($(Get-ArchName $appMachine))"
    Write-Log "汉化包: $packageFolder"

    $prefInfo = Get-PrefLocaleInfo -Path $prefsPath -Encoding $prefsEncoding
    $prefBackupRel = $null
    if ($prefInfo.Exists) {
        $prefBackupRel = 'preferences.ini'
        Copy-Item -LiteralPath $prefsPath -Destination (Join-Path $backupDir $prefBackupRel) -Force
    }

    $manifest = [ordered]@{
        schema             = 1
        createdAt          = (Get-Date).ToString('o')
        completedAt        = $null
        success            = $false
        installPath        = $install
        installVersion     = $appVersion
        installMachine     = ('0x{0:X4}' -f $appMachine)
        packageFolder      = $packageFolder
        packageTitle       = [string]$job.packageTitle
        replaceTray        = $replaceTray
        messagesDirExisted = [bool]$messagesDirExisted
        files              = @()
        tray               = $null
        preferences        = [ordered]@{
            path           = $prefsPath
            existed        = [bool]$prefInfo.Exists
            backup         = $prefBackupRel
            localeExisted  = [bool]$prefInfo.LocaleExisted
            previousLocale = $prefInfo.PreviousLocale
        }
    }

    $fileSpecs = @(
        @{ Name = 'vmui-zh_CN.dll'; Rel = 'messages\zh_CN\vmui-zh_CN.dll' },
        @{ Name = 'vmappsdk-zh_CN.dll'; Rel = 'messages\zh_CN\vmappsdk-zh_CN.dll' },
        @{ Name = 'vmware.vmsg'; Rel = 'messages\zh_CN\vmware.vmsg' }
    )
    $fileEntries = @()
    foreach ($spec in $fileSpecs) {
        $source = Join-Path $packageDir $spec.Name
        $target = Resolve-InstallChildPath -InstallPath $install -RelativePath $spec.Rel
        $entry = [ordered]@{
            target         = $spec.Rel
            sourceHash     = Get-Sha256 $source
            existed        = $false
            backup         = $null
            originalSha256 = $null
            deployedSha256 = $null
        }
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $entry['existed'] = $true
            $entry['originalSha256'] = Get-Sha256 $target
            $backupRel = 'files\' + $spec.Name
            Copy-Item -LiteralPath $target -Destination (Join-Path $backupDir $backupRel) -Force
            if ((Get-Sha256 (Join-Path $backupDir $backupRel)) -ne $entry['originalSha256']) {
                throw "备份校验失败: $($spec.Rel)"
            }
            $entry['backup'] = $backupRel
        }
        $fileEntries += $entry
    }
    $manifest['files'] = $fileEntries

    if ($replaceTray) {
        $trayTarget = Resolve-InstallChildPath -InstallPath $install -RelativePath 'vmware-tray.exe'
        $trayEntry = [ordered]@{
            target         = 'vmware-tray.exe'
            sourceHash     = Get-Sha256 $traySource
            existed        = $false
            backup         = $null
            originalSha256 = $null
            deployedSha256 = $null
        }
        if (Test-Path -LiteralPath $trayTarget -PathType Leaf) {
            $trayEntry['existed'] = $true
            $trayEntry['originalSha256'] = Get-Sha256 $trayTarget
            $backupRel = 'files\vmware-tray.exe'
            Copy-Item -LiteralPath $trayTarget -Destination (Join-Path $backupDir $backupRel) -Force
            if ((Get-Sha256 (Join-Path $backupDir $backupRel)) -ne $trayEntry['originalSha256']) {
                throw '托盘程序备份校验失败。'
            }
            $trayEntry['backup'] = $backupRel
        }
        $manifest['tray'] = $trayEntry
    }

    $manifestPath = Join-Path $backupDir 'manifest.json'
    ($manifest | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    try {
        if ($running.Count -gt 0) {
            Write-Log '正在结束 VMware Workstation 进程...' 'WARN'
            $running | Stop-Process -Force -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddSeconds(15)
            while ((Get-Process -Name vmware -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 500
            }
            Start-Sleep -Milliseconds 1000
            if (Get-Process -Name vmware -ErrorAction SilentlyContinue) {
                throw '无法结束 VMware Workstation 进程，请手动关闭后重试。'
            }
        }

        $trayStopped = $false
        if ($replaceTray) {
            $trayProcesses = @(Get-Process -Name vmware-tray -ErrorAction SilentlyContinue)
            if ($trayProcesses.Count -gt 0) {
                $trayProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                $trayStopped = $true
                Start-Sleep -Milliseconds 800
            }
        }

        if (-not (Test-Path -LiteralPath $messageDir)) {
            New-Item -ItemType Directory -Path $messageDir -Force | Out-Null
        }

        foreach ($entry in $fileEntries) {
            $source = Join-Path $packageDir (Split-Path -Leaf ([string]$entry['target']))
            $target = Resolve-InstallChildPath -InstallPath $install -RelativePath ([string]$entry['target'])
            Copy-Item -LiteralPath $source -Destination $target -Force
            $deployedHash = Get-Sha256 $target
            if ($deployedHash -ne $entry['sourceHash']) { throw "写入校验失败: $($entry['target'])" }
            $entry['deployedSha256'] = $deployedHash
            Write-Log "已写入 $($entry['target'])"
        }

        if ($replaceTray) {
            $trayTarget = Resolve-InstallChildPath -InstallPath $install -RelativePath 'vmware-tray.exe'
            Copy-Item -LiteralPath $traySource -Destination $trayTarget -Force
            $deployedHash = Get-Sha256 $trayTarget
            if ($deployedHash -ne $manifest['tray']['sourceHash']) { throw '托盘程序写入校验失败。' }
            $manifest['tray']['deployedSha256'] = $deployedHash
            Write-Log '已替换托盘程序 vmware-tray.exe'
        }

        Set-PrefLocale -Path $prefsPath -Locale 'zh_CN' -Encoding $prefsEncoding
        $prefVerify = Get-PrefLocaleInfo -Path $prefsPath -Encoding $prefsEncoding
        if (-not $prefVerify.LocaleExisted -or $prefVerify.PreviousLocale -ne 'zh_CN') {
            throw '写入 pref.locale 失败。'
        }
        Write-Log '已设置默认语言 pref.locale = "zh_CN"'

        $manifest['success'] = $true
        $manifest['completedAt'] = (Get-Date).ToString('o')
        ($manifest | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        Write-Log '部署完成。'
        Write-ElevatedResult -Path $ResultPath -Ok $true -Message '部署成功。' -Data @{
            backupDir     = $backupDir
            installPath   = $install
            packageTitle  = [string]$job.packageTitle
            trayReplaced  = $replaceTray
            trayStopped   = $trayStopped
            manifestPath  = $manifestPath
        }
        return 0
    } catch {
        $message = $_.Exception.Message
        Write-Log "部署失败: $message" 'ERROR'
        try {
            Invoke-Rollback -Manifest $manifest -BackupDir $backupDir -InstallPath $install
            $message += ' 已自动回滚到部署前状态。'
        } catch {
            $message += " 自动回滚失败：$($_.Exception.Message) 请运行 restore.ps1 并选择备份目录 $backupDir"
        }
        Write-ElevatedResult -Path $ResultPath -Ok $false -Message $message -Data @{ backupDir = $backupDir }
        return 1
    }
}

if ($Elevated) {
    $exitCode = 1
    try {
        if ([string]::IsNullOrWhiteSpace($JobFile) -or [string]::IsNullOrWhiteSpace($ResultFile)) {
            throw '提权子进程缺少任务参数。'
        }
        $exitCode = Invoke-ElevatedDeploy -JobPath $JobFile -ResultPath $ResultFile
    } catch {
        Write-Host ('错误: ' + $_.Exception.Message) -ForegroundColor Red
        Write-ElevatedResult -Path $ResultFile -Ok $false -Message $_.Exception.Message -Data @{}
        $exitCode = 1
    }
    exit $exitCode
}

Write-Title 'VMware Workstation 简体中文汉化部署'
Write-Host '本工具会安装简体中文资源，并将默认启动语言设为中文。' -ForegroundColor Gray
Write-Host '部署前会自动备份原有文件，可使用 restore.ps1 还原。' -ForegroundColor Gray

$appInfo = Select-InstallPath
if ($null -eq $appInfo) { Write-Host '已取消。'; return }
Write-Host ''
Write-Host "安装目录: $($appInfo.Path)"
Write-Host "程序版本: $($appInfo.Version)"
Write-Host "程序架构: $(Get-ArchName $appInfo.Machine)"

$packages = @(Get-PackageList)
if (@($packages | Where-Object { $_.Available }).Count -eq 0) {
    throw '未找到可用的汉化包，请确认 17-official-zh_CN 与 full-zh_CN 目录完整。'
}

$defaultIndex = 0
for ($i = 0; $i -lt $packages.Count; $i++) {
    $item = $packages[$i]
    $archOk = $item.Available -and ($item.Machine -eq $appInfo.Machine)
    $majorOk = $item.ExpectMajor -eq $appInfo.Major
    if ($archOk -and $majorOk) { $defaultIndex = $i + 1; break }
    if ($archOk -and $defaultIndex -eq 0) { $defaultIndex = $i + 1 }
}
if ($defaultIndex -eq 0) { $defaultIndex = 1 }

Write-Host ''
Write-Host '可用的汉化包：'
for ($i = 0; $i -lt $packages.Count; $i++) {
    $item = $packages[$i]
    $notes = @()
    if (-not $item.Available) {
        $notes += $item.Status
    } else {
        $notes += (Get-ArchName $item.Machine)
        if ($item.Machine -ne $appInfo.Machine) {
            $notes += '架构不匹配'
        } elseif ($item.ExpectMajor -ne $appInfo.Major) {
            $notes += "面向 $($item.ExpectMajor).x，当前为 $($appInfo.Major).x"
        } elseif ($item.BuildHint -and -not ([string]$appInfo.Version).Contains([string]$item.BuildHint)) {
            $notes += "基于构建 $($item.BuildHint)，当前版本不同"
        } else {
            $notes += '兼容'
        }
    }
    $mark = if (($i + 1) -eq $defaultIndex) { '（推荐）' } else { '' }
    Write-Host ('  [{0}] {1}{2}' -f ($i + 1), $item.Title, $mark) -ForegroundColor White
    Write-Host ('      {0}；{1}' -f $item.Description, ($notes -join '；')) -ForegroundColor Gray
}

$selectedPackage = $null
while ($true) {
    $answer = Read-Host "请选择汉化包 [1-$($packages.Count)]（默认 $defaultIndex，输入 q 退出）"
    if ($answer -match '^\s*q\s*$') { Write-Host '已取消。'; return }
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = [string]$defaultIndex }
    $index = 0
    if (-not ([int]::TryParse($answer, [ref]$index) -and $index -ge 1 -and $index -le $packages.Count)) {
        Write-Host '输入无效，请重试。' -ForegroundColor Yellow
        continue
    }
    $item = $packages[$index - 1]
    if (-not $item.Available) {
        Write-Host ('该汉化包不可用: ' + $item.Status) -ForegroundColor Yellow
        continue
    }
    if ($item.Machine -ne $appInfo.Machine) {
        Write-Host ('该汉化包为 {0}，当前程序为 {1}，无法混用。' -f (Get-ArchName $item.Machine), (Get-ArchName $appInfo.Machine)) -ForegroundColor Yellow
        continue
    }
    if ($item.ExpectMajor -ne $appInfo.Major) {
        Write-Host ('注意：该汉化包面向 {0}.x，当前安装为 {1}。' -f $item.ExpectMajor, $appInfo.Version) -ForegroundColor Yellow
        if (-not (Read-YesNo '版本不一致，仍要继续吗？' $false)) { continue }
    } elseif ($item.BuildHint -and -not ([string]$appInfo.Version).Contains([string]$item.BuildHint)) {
        Write-Host ('注意：该汉化包基于构建 {0}，当前安装为 {1}，可能有少量文本差异。' -f $item.BuildHint, $appInfo.Version) -ForegroundColor Yellow
        if (-not (Read-YesNo '仍要继续吗？' $true)) { continue }
    }
    $selectedPackage = $item
    break
}

$packageDir = Join-Path $ScriptRoot $selectedPackage.Folder
$hasTray = Test-Path -LiteralPath (Join-Path $packageDir 'vmware-tray.exe') -PathType Leaf
$replaceTray = $false
if ($hasTray) {
    Write-Host ''
    $replaceTray = Read-YesNo '是否同时替换托盘程序 vmware-tray.exe（中文托盘菜单和提示）？' $selectedPackage.TrayDefault
} else {
    Write-Host '该汉化包不包含托盘程序，将保留现有托盘。' -ForegroundColor Gray
}

$closeVmware = $false
$running = @(Get-Process -Name vmware -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Write-Host ''
    Write-Host '检测到 VMware Workstation 正在运行。' -ForegroundColor Yellow
    Write-Host '部署前必须关闭 VMware 和所有虚拟机，否则语言文件被占用，且未保存的状态可能丢失。' -ForegroundColor Yellow
    $closeVmware = Read-YesNo '是否结束 VMware 进程并继续？' $false
    if (-not $closeVmware) {
        Write-Host '已取消。请手动关闭 VMware 后重试。'
        return
    }
}
$vmxCount = @(Get-Process -Name vmware-vmx -ErrorAction SilentlyContinue).Count
if ($vmxCount -gt 0) {
    Write-Host "检测到 $vmxCount 个正在运行的虚拟机进程，部署不会结束它们。" -ForegroundColor Yellow
    Write-Host '建议先关闭虚拟机，避免部署后界面与虚拟机状态不同步。' -ForegroundColor Yellow
    if (-not (Read-YesNo '仍要继续吗？' $false)) { Write-Host '已取消。'; return }
}

Write-Host ''
Write-Host '即将执行：' -ForegroundColor Cyan
Write-Host "  安装目录 : $($appInfo.Path)"
Write-Host "  汉化包   : $($selectedPackage.Title)（$($selectedPackage.Description)）"
Write-Host "  托盘程序 : $(if ($replaceTray) { '替换' } else { '保留' })"
Write-Host "  备份位置 : $(Join-Path $ScriptRoot 'backup')\<时间戳>"
if (-not (Read-YesNo '确认继续并请求管理员权限？' $true)) { Write-Host '已取消。'; return }

$job = @{
    installPath   = $appInfo.Path
    packageFolder = $selectedPackage.Folder
    packageTitle  = $selectedPackage.Title
    replaceTray   = [bool]$replaceTray
    closeVmware   = [bool]$closeVmware
    userAppData   = [string]$env:APPDATA
}

$invokeResult = Invoke-ElevatedChild -Job $job
if ($invokeResult.Canceled) {
    Write-Host '已取消管理员授权，未做任何修改。' -ForegroundColor Yellow
    return
}

if ($null -ne $invokeResult.Result -and [bool]$invokeResult.Result.success) {
    $data = $invokeResult.Result.data
    Write-Host ''
    Write-Host '部署成功。' -ForegroundColor Green
    Write-Host "  汉化包   : $($selectedPackage.Title)"
    Write-Host "  安装目录 : $($appInfo.Path)"
    Write-Host "  托盘程序 : $(if ($replaceTray) { '已替换' } else { '未替换' })"
    if ($data -and $data.backupDir) {
        Write-Host "  备份目录 : $($data.backupDir)"
        Write-Host '  如需还原，请运行 restore.ps1 并选择该备份。'
    }
    Start-TrayIfNeeded -InstallPath $appInfo.Path
    Write-Host '现在可以启动 VMware Workstation，界面和托盘应显示为简体中文。' -ForegroundColor Green
} else {
    Write-Host ''
    Write-Host '部署失败。' -ForegroundColor Red
    if ($invokeResult.Result -and $invokeResult.Result.message) {
        Write-Host ('原因: ' + [string]$invokeResult.Result.message) -ForegroundColor Red
    } elseif ($invokeResult.Error) {
        Write-Host ('原因: ' + $invokeResult.Error) -ForegroundColor Red
    }
    if ($invokeResult.Result -and $invokeResult.Result.data -and $invokeResult.Result.data.backupDir) {
        Write-Host "备份目录: $($invokeResult.Result.data.backupDir)"
    }
    Write-Host '如文件已部分修改，可运行 restore.ps1 还原。' -ForegroundColor Yellow
    exit 1
}
