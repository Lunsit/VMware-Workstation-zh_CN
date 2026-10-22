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

function Test-VmwareInstallPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($Path.Trim().Trim('"')) } catch { return $false }
    return (Test-Path -LiteralPath (Join-Path $full 'vmware.exe') -PathType Leaf)
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

function Get-ObjValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function Read-ManifestFile {
    param([string]$Path)
    try {
        return ((Get-Content -LiteralPath $Path -Raw -Encoding UTF8) | ConvertFrom-Json)
    } catch {
        return $null
    }
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

function Resolve-BackupChildPath {
    param([string]$BackupDir, [string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath)) { throw '备份记录无效。' }
    if ([System.IO.Path]::IsPathRooted($RelativePath)) { throw '备份记录包含绝对路径，已拒绝。' }
    $root = [System.IO.Path]::GetFullPath($BackupDir).TrimEnd('\')
    $full = [System.IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    if (-not $full.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "备份路径越界: $RelativePath"
    }
    return $full
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
    $jobPath = Join-Path $publicDir "vmware-zhrestore-$id.json"
    $resultPath = Join-Path $publicDir "vmware-zhrestore-$id.result.json"
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
        Write-Host "托盘程序未能自动启动，请手动运行: $tray" -ForegroundColor Yellow
    }
}

function Invoke-ElevatedRestore {
    param([string]$JobPath, [string]$ResultPath)
    $job = (Get-Content -LiteralPath $JobPath -Raw -Encoding UTF8) | ConvertFrom-Json

    $backupRoot = [System.IO.Path]::GetFullPath((Join-Path $ScriptRoot 'backup')).TrimEnd('\')
    $backupDir = [System.IO.Path]::GetFullPath(([string]$job.backupDir)).TrimEnd('\')
    if (-not $backupDir.StartsWith($backupRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw '备份目录无效。'
    }
    $manifestPath = Join-Path $backupDir 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw '备份目录中缺少 manifest.json。' }
    $manifest = Read-ManifestFile $manifestPath
    if ($null -eq $manifest) { throw '无法读取备份清单 manifest.json。' }

    $install = ([string]$job.installPath).TrimEnd('\')
    if (-not (Test-VmwareInstallPath $install)) { throw "安装目录无效或其中没有 vmware.exe: $install" }
    $install = ([System.IO.Path]::GetFullPath($install)).TrimEnd('\')
    $script:LogFile = Join-Path $backupDir 'restore.log'
    Write-Log '开始恢复汉化前的状态'
    Write-Log "安装目录: $install"
    Write-Log "备份目录: $backupDir"

    $fileEntries = @()
    $rawFiles = Get-ObjValue $manifest 'files' $null
    if ($rawFiles) { $fileEntries = @($rawFiles) }

    foreach ($entry in $fileEntries) {
        $relative = [string](Get-ObjValue $entry 'target' '')
        $null = Resolve-InstallChildPath -InstallPath $install -RelativePath $relative
        if ([bool](Get-ObjValue $entry 'existed' $false)) {
            $backupRel = [string](Get-ObjValue $entry 'backup' '')
            if ([string]::IsNullOrWhiteSpace($backupRel)) { throw "备份清单缺少文件记录: $relative" }
            $backupPath = Resolve-BackupChildPath -BackupDir $backupDir -RelativePath $backupRel
            if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) { throw "备份文件缺失: $backupRel" }
        }
    }

    $replaceTray = [bool](Get-ObjValue $manifest 'replaceTray' $false)
    $trayEntry = Get-ObjValue $manifest 'tray' $null
    if ($fileEntries.Count -eq 0 -and -not $replaceTray) {
        throw '备份清单中没有可恢复的文件记录。'
    }
    if ($replaceTray) {
        $null = Resolve-InstallChildPath -InstallPath $install -RelativePath 'vmware-tray.exe'
        if ($null -eq $trayEntry) { throw '备份清单缺少托盘程序记录。' }
        if ([bool](Get-ObjValue $trayEntry 'existed' $false)) {
            $trayBackupRel = [string](Get-ObjValue $trayEntry 'backup' '')
            if ([string]::IsNullOrWhiteSpace($trayBackupRel)) { throw '备份清单缺少托盘程序文件记录。' }
            $trayBackupPath = Resolve-BackupChildPath -BackupDir $backupDir -RelativePath $trayBackupRel
            if (-not (Test-Path -LiteralPath $trayBackupPath -PathType Leaf)) { throw "托盘程序备份缺失: $trayBackupRel" }
        }
    }

    $pref = Get-ObjValue $manifest 'preferences' $null
    $prefsPath = [string](Get-ObjValue $pref 'path' '')
    if ([string]::IsNullOrWhiteSpace($prefsPath)) {
        $userAppData = [string]$job.userAppData
        if (-not [string]::IsNullOrWhiteSpace($userAppData)) {
            $prefsPath = Join-Path $userAppData 'VMware\preferences.ini'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($prefsPath)) {
        if (-not [System.IO.Path]::IsPathRooted($prefsPath)) { throw '偏好设置路径无效。' }
        if ((Split-Path -Leaf $prefsPath) -ne 'preferences.ini') { throw '偏好设置路径无效。' }
    }

    $closeVmware = [bool]$job.closeVmware
    $running = @(Get-Process -Name vmware -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        if (-not $closeVmware) { throw 'VMware Workstation 正在运行，请关闭后重试。' }
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

    try {
        $restoredCount = 0
        $removedCount = 0
        foreach ($entry in $fileEntries) {
            $relative = [string](Get-ObjValue $entry 'target' '')
            $target = Resolve-InstallChildPath -InstallPath $install -RelativePath $relative
            $targetDir = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
            if ([bool](Get-ObjValue $entry 'existed' $false)) {
                $backupRel = [string](Get-ObjValue $entry 'backup' '')
                $backupPath = Resolve-BackupChildPath -BackupDir $backupDir -RelativePath $backupRel
                Copy-Item -LiteralPath $backupPath -Destination $target -Force
                $expected = [string](Get-ObjValue $entry 'originalSha256' '')
                if ($expected -and (Get-Sha256 $target) -ne $expected) { throw "恢复校验失败: $relative" }
                $restoredCount++
                Write-Log "已恢复 $relative"
            } elseif (Test-Path -LiteralPath $target) {
                Remove-Item -LiteralPath $target -Force
                $removedCount++
                Write-Log "已删除部署的文件 $relative"
            }
        }

        $trayRestored = $false
        if ($replaceTray -and $trayEntry) {
            $trayTarget = Resolve-InstallChildPath -InstallPath $install -RelativePath 'vmware-tray.exe'
            if ([bool](Get-ObjValue $trayEntry 'existed' $false)) {
                $trayBackupRel = [string](Get-ObjValue $trayEntry 'backup' '')
                $trayBackupPath = Resolve-BackupChildPath -BackupDir $backupDir -RelativePath $trayBackupRel
                Copy-Item -LiteralPath $trayBackupPath -Destination $trayTarget -Force
                $expected = [string](Get-ObjValue $trayEntry 'originalSha256' '')
                if ($expected -and (Get-Sha256 $trayTarget) -ne $expected) { throw '托盘程序恢复校验失败。' }
                $trayRestored = $true
                Write-Log '已恢复托盘程序 vmware-tray.exe'
            } elseif (Test-Path -LiteralPath $trayTarget) {
                Remove-Item -LiteralPath $trayTarget -Force
                Write-Log '已删除部署的托盘程序 vmware-tray.exe'
            }
        }

        $prefAction = '未修改'
        if ($pref -and -not [string]::IsNullOrWhiteSpace($prefsPath)) {
            $prefEncoding = Get-PrefEncoding
            $localeExisted = [bool](Get-ObjValue $pref 'localeExisted' $false)
            $previousLocale = [string](Get-ObjValue $pref 'previousLocale' '')
            if ($localeExisted -and -not [string]::IsNullOrWhiteSpace($previousLocale)) {
                Set-PrefLocale -Path $prefsPath -Locale $previousLocale -Encoding $prefEncoding
                $prefAction = "已恢复为 $previousLocale"
            } else {
                Remove-PrefLocale -Path $prefsPath -Encoding $prefEncoding
                $prefAction = '已移除 pref.locale'
            }
            $prefExisted = [bool](Get-ObjValue $pref 'existed' $true)
            if (-not $prefExisted -and (Test-Path -LiteralPath $prefsPath)) {
                $remaining = [System.IO.File]::ReadAllText($prefsPath, $prefEncoding)
                if ([string]::IsNullOrWhiteSpace($remaining)) {
                    Remove-Item -LiteralPath $prefsPath -Force
                    $prefAction += '，并删除空的首选项文件'
                }
            }
            Write-Log "语言设置: $prefAction"
        }

        if (-not [bool](Get-ObjValue $manifest 'messagesDirExisted' $true)) {
            $messageDir = Join-Path $install 'messages\zh_CN'
            if ((Test-Path -LiteralPath $messageDir) -and @(Get-ChildItem -LiteralPath $messageDir -Force).Count -eq 0) {
                Remove-Item -LiteralPath $messageDir -Force
                Write-Log '已删除部署创建的 messages\zh_CN 目录'
            }
        }

        Write-Log '恢复完成。'
        Write-ElevatedResult -Path $ResultPath -Ok $true -Message '恢复成功。' -Data @{
            backupDir     = $backupDir
            installPath   = $install
            restoredFiles = $restoredCount
            removedFiles  = $removedCount
            trayRestored  = $trayRestored
            trayStopped   = $trayStopped
            preferences   = $prefAction
        }
        return 0
    } catch {
        $message = $_.Exception.Message
        Write-Log "恢复失败: $message" 'ERROR'
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
        $exitCode = Invoke-ElevatedRestore -JobPath $JobFile -ResultPath $ResultFile
    } catch {
        Write-Host ('错误: ' + $_.Exception.Message) -ForegroundColor Red
        Write-ElevatedResult -Path $ResultFile -Ok $false -Message $_.Exception.Message -Data @{}
        $exitCode = 1
    }
    exit $exitCode
}

Write-Title 'VMware Workstation 简体中文汉化恢复'
Write-Host '从部署备份中恢复原文件、托盘程序和默认语言设置。' -ForegroundColor Gray

$backupRoot = Join-Path $ScriptRoot 'backup'
if (-not (Test-Path -LiteralPath $backupRoot)) {
    Write-Host '未找到 backup 目录，没有可恢复的备份。' -ForegroundColor Yellow
    return
}
$backupDirs = @(
    Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json') -PathType Leaf } |
        Sort-Object Name -Descending
)
if ($backupDirs.Count -eq 0) {
    Write-Host '没有找到包含 manifest.json 的备份。' -ForegroundColor Yellow
    return
}

Write-Host ''
Write-Host '可用备份（最新在前）：'
for ($i = 0; $i -lt $backupDirs.Count; $i++) {
    $info = Read-ManifestFile (Join-Path $backupDirs[$i].FullName 'manifest.json')
    $title = [string](Get-ObjValue $info 'packageTitle' '未知包')
    $version = [string](Get-ObjValue $info 'installVersion' '')
    $path = [string](Get-ObjValue $info 'installPath' '')
    $state = if ([bool](Get-ObjValue $info 'success' $false)) { '部署成功' } else { '部署未完成' }
    Write-Host ('  [{0}] {1}  {2}  {3}  {4}' -f ($i + 1), $backupDirs[$i].Name, $title, $version, $state)
    Write-Host ('      {0}' -f $path) -ForegroundColor Gray
}

$selected = $null
while ($true) {
    $answer = Read-Host "请选择要恢复的备份 [1-$($backupDirs.Count)]（默认 1，输入 q 退出）"
    if ($answer -match '^\s*q\s*$') { Write-Host '已取消。'; return }
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = '1' }
    $index = 0
    if ([int]::TryParse($answer, [ref]$index) -and $index -ge 1 -and $index -le $backupDirs.Count) {
        $selected = $backupDirs[$index - 1]
        break
    }
    Write-Host '输入无效，请重试。' -ForegroundColor Yellow
}

$manifest = Read-ManifestFile (Join-Path $selected.FullName 'manifest.json')
if ($null -eq $manifest) {
    Write-Host '该备份的 manifest.json 无法读取，已取消。' -ForegroundColor Red
    return
}

$install = [string](Get-ObjValue $manifest 'installPath' '')
if (-not (Test-VmwareInstallPath $install)) {
    Write-Host "备份记录的安装目录不可用: $install" -ForegroundColor Yellow
    $install = Read-InstallPathFromUser
    if ($null -eq $install) { Write-Host '已取消。'; return }
}
$install = ([System.IO.Path]::GetFullPath($install)).TrimEnd('\')

$backupVersion = [string](Get-ObjValue $manifest 'installVersion' '')
$currentVersion = [string](Get-Item -LiteralPath (Join-Path $install 'vmware.exe')).VersionInfo.ProductVersion
Write-Host ''
Write-Host "安装目录: $install"
Write-Host "当前版本: $currentVersion"
Write-Host "备份版本: $backupVersion"
Write-Host "备份目录: $($selected.FullName)"
if ($backupVersion -and $backupVersion -ne $currentVersion) {
    Write-Host '注意：当前安装版本与备份时不一致。' -ForegroundColor Yellow
    if (-not (Read-YesNo '仍要按该备份恢复吗？' $false)) { Write-Host '已取消。'; return }
}

$closeVmware = $false
$running = @(Get-Process -Name vmware -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Write-Host '检测到 VMware Workstation 正在运行。' -ForegroundColor Yellow
    Write-Host '恢复前必须关闭 VMware 和所有虚拟机。' -ForegroundColor Yellow
    $closeVmware = Read-YesNo '是否结束 VMware 进程并继续？' $false
    if (-not $closeVmware) {
        Write-Host '已取消。请手动关闭 VMware 后重试。'
        return
    }
}

$replaceTray = [bool](Get-ObjValue $manifest 'replaceTray' $false)
Write-Host ''
Write-Host '即将恢复：'
Write-Host "  安装目录 : $install"
Write-Host "  备份目录 : $($selected.FullName)"
Write-Host "  托盘程序 : $(if ($replaceTray) { '恢复部署前的文件' } else { '未由本工具修改' })"
Write-Host "  默认语言 : 恢复部署前的 pref.locale 设置"
if (-not (Read-YesNo '确认继续并请求管理员权限？' $true)) { Write-Host '已取消。'; return }

$job = @{
    backupDir   = $selected.FullName
    installPath = $install
    closeVmware = [bool]$closeVmware
    userAppData = [string]$env:APPDATA
}

$invokeResult = Invoke-ElevatedChild -Job $job
if ($invokeResult.Canceled) {
    Write-Host '已取消管理员授权，未做任何修改。' -ForegroundColor Yellow
    return
}

if ($null -ne $invokeResult.Result -and [bool]$invokeResult.Result.success) {
    $data = $invokeResult.Result.data
    Write-Host ''
    Write-Host '恢复成功。' -ForegroundColor Green
    Write-Host "  安装目录 : $install"
    if ($data) {
        Write-Host "  已恢复文件: $([int](Get-ObjValue $data 'restoredFiles' 0)) 个"
        Write-Host "  已删除文件: $([int](Get-ObjValue $data 'removedFiles' 0)) 个"
        Write-Host "  语言设置  : $([string](Get-ObjValue $data 'preferences' '未修改'))"
    }
    if ($data -and [bool](Get-ObjValue $data 'trayStopped' $false)) {
        Start-TrayIfNeeded -InstallPath $install
    }
    Write-Host '启动 VMware Workstation 后即为恢复后的语言。' -ForegroundColor Green
} else {
    Write-Host ''
    Write-Host '恢复失败。' -ForegroundColor Red
    if ($invokeResult.Result -and $invokeResult.Result.message) {
        Write-Host ('原因: ' + [string]$invokeResult.Result.message) -ForegroundColor Red
    } elseif ($invokeResult.Error) {
        Write-Host ('原因: ' + $invokeResult.Error) -ForegroundColor Red
    }
    Write-Host '可以重新运行 restore.ps1 重试；原始文件仍在备份目录中。' -ForegroundColor Yellow
    exit 1
}
