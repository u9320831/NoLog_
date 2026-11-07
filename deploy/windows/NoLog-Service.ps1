[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Uninstall", "Start", "Stop", "Restart", "Status")]
    [string]$Action,

    [string]$ServiceName = "NoLog",
    [string]$ExecutablePath,
    [string]$Arguments = "",
    [string]$WorkingDirectory,
    [string]$NssmPath,
    [switch]$DownloadNssm,
    [switch]$StartAfterInstall
)

$ErrorActionPreference = "Stop"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Nssm {
    param([string[]]$Arguments)

    & $script:Nssm @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "NSSM a échoué avec le code $LASTEXITCODE : $($Arguments -join ' ')"
    }
}

function Resolve-Nssm {
    if ($NssmPath) {
        $resolved = [IO.Path]::GetFullPath($NssmPath)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "NSSM introuvable : $resolved"
        }
        return $resolved
    }

    $command = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $localCandidates = @(
        (Join-Path $PSScriptRoot "..\tools\nssm\win64\nssm.exe"),
        (Join-Path $PSScriptRoot "..\tools\nssm\win32\nssm.exe")
    )
    foreach ($candidate in $localCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [IO.Path]::GetFullPath($candidate)
        }
    }

    if (-not $DownloadNssm) {
        throw "NSSM est introuvable. Fournir -NssmPath ou utiliser -DownloadNssm."
    }

    $toolsRoot = Join-Path $PSScriptRoot "..\tools\nssm"
    $archive = Join-Path $env:TEMP "nssm-2.24-101.zip"
    $downloadUrl = "https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip"
    New-Item -ItemType Directory -Force -Path $toolsRoot | Out-Null
    Write-Host "Téléchargement de NSSM depuis la source officielle : $downloadUrl"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archive
    Expand-Archive -LiteralPath $archive -DestinationPath $toolsRoot -Force

    $downloaded = Get-ChildItem -LiteralPath $toolsRoot -Filter nssm.exe -Recurse -File |
        Where-Object { $_.FullName -match "win64" } |
        Select-Object -First 1
    if (-not $downloaded) {
        throw "NSSM téléchargé mais nssm.exe win64 est introuvable."
    }
    return $downloaded.FullName
}

function Assert-ServiceActionAllowed {
    if (-not (Test-Administrator)) {
        throw "Cette action doit être exécutée dans PowerShell en tant qu'administrateur."
    }
}

if ($Action -in @("Install", "Uninstall", "Start", "Stop", "Restart")) {
    Assert-ServiceActionAllowed
}

$script:Nssm = $null
if ($Action -ne "Status") {
    $script:Nssm = Resolve-Nssm
}

switch ($Action) {
    "Install" {
        if (-not $ExecutablePath) {
            throw "-ExecutablePath est obligatoire pour installer le service."
        }

        $application = [IO.Path]::GetFullPath($ExecutablePath)
        if (-not (Test-Path -LiteralPath $application -PathType Leaf)) {
            throw "Exécutable introuvable : $application"
        }

        if (-not $WorkingDirectory) {
            $WorkingDirectory = Split-Path -Parent $application
        } else {
            $WorkingDirectory = [IO.Path]::GetFullPath($WorkingDirectory)
        }
        if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
            throw "Répertoire de travail introuvable : $WorkingDirectory"
        }

        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            throw "Le service $ServiceName existe déjà. Utiliser -Action Uninstall d'abord."
        }

        Invoke-Nssm @("install", $ServiceName)
        Invoke-Nssm @("set", $ServiceName, "Application", $application)
        Invoke-Nssm @("set", $ServiceName, "AppDirectory", $WorkingDirectory)
        if ($Arguments) {
            Invoke-Nssm @("set", $ServiceName, "AppParameters", $Arguments)
        }
        Invoke-Nssm @("set", $ServiceName, "DisplayName", "NoLog")
        Invoke-Nssm @("set", $ServiceName, "Description", "NoLog host application")
        Invoke-Nssm @("set", $ServiceName, "Start", "SERVICE_AUTO_START")
        Invoke-Nssm @("set", $ServiceName, "ObjectName", "NT AUTHORITY\LocalService")
        Invoke-Nssm @("set", $ServiceName, "AppExit", "Default", "Restart")
        Invoke-Nssm @("set", $ServiceName, "AppRestartDelay", "5000")

        Write-Host "Service $ServiceName installé."
        Write-Host "Compte : NT AUTHORITY\LocalService"
        Write-Host "Aucun stdout/stderr n'est redirigé vers un fichier par défaut."

        if ($StartAfterInstall) {
            Invoke-Nssm @("start", $ServiceName)
            Write-Host "Service démarré."
        }
    }
    "Uninstall" {
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $existing) {
            Write-Host "Service $ServiceName absent."
            break
        }
        Invoke-Nssm @("stop", $ServiceName)
        Invoke-Nssm @("remove", $ServiceName, "confirm")
        Write-Host "Service $ServiceName supprimé."
    }
    "Start" {
        Invoke-Nssm @("start", $ServiceName)
        Invoke-Nssm @("status", $ServiceName)
    }
    "Stop" {
        Invoke-Nssm @("stop", $ServiceName)
        Invoke-Nssm @("status", $ServiceName)
    }
    "Restart" {
        Invoke-Nssm @("restart", $ServiceName)
        Invoke-Nssm @("status", $ServiceName)
    }
    "Status" {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Host "Service $ServiceName absent."
        } else {
            $service | Select-Object Name, DisplayName, Status, StartType
        }
    }
}
