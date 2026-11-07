[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Up", "Down", "Restart", "Status", "Logs")]
    [string]$Action,

    [switch]$Tor,
    [string]$Service = ""
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
    throw "Docker Desktop et Docker Compose sont requis."
}

$composeFile = Join-Path $PSScriptRoot "..\docker-compose.yml"
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw "Fichier Compose introuvable : $composeFile"
}

$composeArgs = @("compose", "-f", $composeFile)
if ($Tor) {
    $composeArgs += @("--profile", "tor")
}

switch ($Action) {
    "Up" {
        $composeArgs += @("up", "--build", "--detach")
    }
    "Down" {
        $composeArgs += @("down")
    }
    "Restart" {
        $composeArgs += @("restart")
    }
    "Status" {
        $composeArgs += @("ps")
    }
    "Logs" {
        $composeArgs += @("logs", "--tail", "100")
        if ($Service) {
            $composeArgs += $Service
        }
    }
}

& docker.exe @composeArgs
exit $LASTEXITCODE
