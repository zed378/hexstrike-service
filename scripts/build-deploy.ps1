# ============================================================================
# HexStrike AI - Build & Deploy (PowerShell)
# Dockerfiles/compose in deploy\ ; build CONTEXT = repo root.
#
# Usage:  scripts\build-deploy.ps1 <command> [image]
#   build [latest|predeploy|postdeploy]   Build all 3, or one
#   push  [latest|predeploy|postdeploy]   Push all, or one
#   pull | up | down | logs | vps-up | vps-down | clean | help
# Env: REGISTRY_IMAGE (default zed378/hexstrike-ai)
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = "help",
    [Parameter(Position = 1)][string]$Image = "all"
)

$ErrorActionPreference = "Stop"

# repo root = parent of this script's dir
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$RegistryImage = if ($env:REGISTRY_IMAGE) { $env:REGISTRY_IMAGE } else { "zed378/hexstrike-ai" }
$ImgLatest     = "${RegistryImage}:latest"
$ImgPre        = "${RegistryImage}:predeploy"
$ImgPost       = "${RegistryImage}:postdeploy"
$ComposeDev    = "deploy/docker-compose.yml"
$ComposeVps    = "deploy/docker-compose.vps.yml"

function Compose {
    param([string]$File, [Parameter(ValueFromRemainingArguments = $true)]$Args)
    if (Test-Path ".env") {
        docker compose --env-file .env -f $File @Args
    } else {
        docker compose -f $File @Args
    }
}

function Build-Image([string]$name) {
    switch ($name) {
        { $_ -in "latest", "full" } { docker build -f deploy/Dockerfile            -t $ImgLatest . }
        "predeploy"                 { docker build -f deploy/Dockerfile.predeploy  -t $ImgPre    . }
        "postdeploy"                { docker build -f deploy/Dockerfile.postdeploy -t $ImgPost   . }
        default { Write-Error "Unknown image: $name (latest|predeploy|postdeploy)" }
    }
}

function Show-Help { Get-Content $PSCommandPath | Select-Object -First 10 | ForEach-Object { $_ -replace '^#\s?', '' } }

switch ($Command) {
    "build" {
        if ($Image -eq "all") { Build-Image "predeploy"; Build-Image "postdeploy"; Build-Image "latest" }
        else { Build-Image $Image }
    }
    "push" {
        switch ($Image) {
            "all"        { docker push $ImgLatest; docker push $ImgPre; docker push $ImgPost }
            "predeploy"  { docker push $ImgPre }
            "postdeploy" { docker push $ImgPost }
            default      { docker push $ImgLatest }
        }
    }
    "pull"     { docker pull $ImgLatest; docker pull $ImgPre; docker pull $ImgPost }
    "up"       { Compose $ComposeDev pull; Compose $ComposeDev up -d hexstrike-server }
    "down"     { Compose $ComposeDev down }
    "logs"     { Compose $ComposeDev logs -f }
    "vps-up"   { Compose $ComposeVps pull; Compose $ComposeVps up -d }
    "vps-down" { Compose $ComposeVps down }
    "clean" {
        try { Compose $ComposeDev down --volumes } catch {}
        foreach ($img in @($ImgLatest, $ImgPre, $ImgPost)) { try { docker rmi $img } catch {} }
    }
    default { Show-Help }
}
