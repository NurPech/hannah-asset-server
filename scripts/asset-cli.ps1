#Requires -Version 7

param(
    [Parameter(Position = 0, Mandatory)]
    [string]$Command,
    [Parameter(Position = 1)][string]$Arg1,
    [Parameter(Position = 2)][string]$Arg2,
    [Parameter(Position = 3)][string]$Arg3
)

$EnvFile = Join-Path $PSScriptRoot ".." ".env"

if (-not (Test-Path $EnvFile)) {
    Write-Error ".env nicht gefunden (erwartet: $EnvFile)`nVorlage: Copy-Item .env.example .env"
    exit 1
}

foreach ($line in Get-Content $EnvFile) {
    if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
    $key, $val = $line -split '=', 2
    Set-Item "env:$($key.Trim())" $val.Trim()
}

if (-not $env:ASSET_SERVER_URL) { Write-Error "ASSET_SERVER_URL fehlt in .env"; exit 1 }
if (-not $env:ASSET_SERVER_TOKEN) { Write-Error "ASSET_SERVER_TOKEN fehlt in .env"; exit 1 }

$Base = $env:ASSET_SERVER_URL.TrimEnd('/')
$Headers = @{ Authorization = "Bearer $env:ASSET_SERVER_TOKEN" }

function Usage {
    @"
Verwendung: asset-cli.ps1 <Befehl> [Argumente]

Befehle:
  health                                          Serverstatus prüfen
  manifest <namespace>                            Manifest abrufen (inkl. geerbter Parent-Assets)
  upload <key> <datei> <namespace>                Asset hochladen (genau ein Ziel-Namespace)
  download <key> <namespace> [ausgabe]            Asset herunterladen (Standard: <key>)
  delete <key> <namespace>                        Asset löschen
  serviceaccounts list                            Service Accounts anzeigen (Name, ID)
  tokens list <service-account>                   Tokens eines Service Accounts anzeigen
  tokens create <service-account> <token-name>    Token erstellen
  tokens delete <service-account> <token-id>      Token widerrufen

<namespace>: z.B. core, satellite, shared, oder ein selbst angelegter Namespace
<service-account>: Name (nicht ID) — siehe 'serviceaccounts list'

Namespace-Rechte eines Service Accounts (namespace:action) werden aktuell nur
über die WebUI (Admin -> Service Accounts) verwaltet, nicht über dieses Script.
"@
    exit 1
}

function Resolve-ServiceAccountId([string]$Name) {
    $accounts = Invoke-RestMethod -Uri "$Base/api/service-accounts" -Headers $Headers
    $sa = $accounts | Where-Object { $_.name -eq $Name }
    if (-not $sa) {
        Write-Error "Service Account '$Name' nicht gefunden — siehe 'asset-cli.ps1 serviceaccounts list'"
        exit 1
    }
    return $sa.id
}

switch ($Command) {

    'health' {
        $r = Invoke-RestMethod -Uri "$Base/health" -Headers $Headers
        Write-Host $r
    }

    'manifest' {
        if (-not $Arg1) { Write-Error "Verwendung: asset-cli.ps1 manifest <namespace>"; exit 1 }
        Invoke-RestMethod -Uri "$Base/manifest?namespace=$Arg1" -Headers $Headers | ConvertTo-Json -Depth 10
    }

    'upload' {
        if (-not $Arg1 -or -not $Arg2 -or -not $Arg3) {
            Write-Error "Verwendung: asset-cli.ps1 upload <key> <datei> <namespace>"
            exit 1
        }
        $key = $Arg1; $file = $Arg2; $namespace = $Arg3
        if (-not (Test-Path $file)) { Write-Error "Datei nicht gefunden: $file"; exit 1 }

        $mime = switch ([System.IO.Path]::GetExtension($file).ToLower()) {
            '.mp3'  { 'audio/mpeg' }
            '.wav'  { 'audio/wav' }
            '.ogg'  { 'audio/ogg' }
            '.flac' { 'audio/flac' }
            '.aac'  { 'audio/aac' }
            '.jpg'  { 'image/jpeg' }
            '.jpeg' { 'image/jpeg' }
            '.png'  { 'image/png' }
            '.gif'  { 'image/gif' }
            '.webp' { 'image/webp' }
            '.mp4'  { 'video/mp4' }
            '.webm' { 'video/webm' }
            default { 'application/octet-stream' }
        }

        Write-Host "Uploading '$file' als '$key' (MIME: $mime, Namespace: $namespace)..."
        $uploadHeaders = $Headers + @{ 'Content-Type' = $mime }
        $body = [System.IO.File]::ReadAllBytes((Resolve-Path $file))
        Invoke-RestMethod -Uri "$Base/namespaces/$namespace/assets/$key" `
            -Method Put -Headers $uploadHeaders -Body $body | ConvertTo-Json
    }

    'download' {
        if (-not $Arg1 -or -not $Arg2) { Write-Error "Verwendung: asset-cli.ps1 download <key> <namespace> [ausgabe]"; exit 1 }
        $key = $Arg1; $namespace = $Arg2
        $out = if ($Arg3) { $Arg3 } else { $key }
        Invoke-RestMethod -Uri "$Base/assets/$key`?namespace=$namespace" -Headers $Headers -OutFile $out
        Write-Host "Gespeichert: $out"
    }

    'delete' {
        if (-not $Arg1 -or -not $Arg2) { Write-Error "Verwendung: asset-cli.ps1 delete <key> <namespace>"; exit 1 }
        Invoke-RestMethod -Uri "$Base/namespaces/$Arg2/assets/$Arg1" -Method Delete -Headers $Headers | Out-Null
        Write-Host "Gelöscht: $Arg1 (namespace: $Arg2)"
    }

    'serviceaccounts' {
        switch ($Arg1) {
            'list' {
                Invoke-RestMethod -Uri "$Base/api/service-accounts" -Headers $Headers | ConvertTo-Json -Depth 5
            }
            default { Write-Error "Unbekannter serviceaccounts-Unterbefehl: $Arg1"; Usage }
        }
    }

    'tokens' {
        switch ($Arg1) {
            'list' {
                if (-not $Arg2) { Write-Error "Verwendung: asset-cli.ps1 tokens list <service-account>"; exit 1 }
                $id = Resolve-ServiceAccountId $Arg2
                $sa = Invoke-RestMethod -Uri "$Base/api/service-accounts/$id" -Headers $Headers
                $sa.tokens | ConvertTo-Json -Depth 5
            }
            'create' {
                if (-not $Arg2 -or -not $Arg3) {
                    Write-Error "Verwendung: asset-cli.ps1 tokens create <service-account> <token-name>"
                    exit 1
                }
                $id = Resolve-ServiceAccountId $Arg2
                $createHeaders = $Headers + @{ 'Content-Type' = 'application/json' }
                $body = @{ name = $Arg3 } | ConvertTo-Json
                $resp = Invoke-RestMethod -Uri "$Base/api/service-accounts/$id/tokens" -Method Post -Headers $createHeaders -Body $body
                $resp | ConvertTo-Json
                Write-Host ""
                Write-Host "!!! Token nur einmalig angezeigt — jetzt sichern !!!" -ForegroundColor Yellow
                Write-Host "Token: $($resp.token)" -ForegroundColor Cyan
            }
            'delete' {
                if (-not $Arg2 -or -not $Arg3) { Write-Error "Verwendung: asset-cli.ps1 tokens delete <service-account> <token-id>"; exit 1 }
                $id = Resolve-ServiceAccountId $Arg2
                Invoke-RestMethod -Uri "$Base/api/service-accounts/$id/tokens/$Arg3" -Method Delete -Headers $Headers | Out-Null
                Write-Host "Token widerrufen: $Arg3"
            }
            default { Write-Error "Unbekannter tokens-Unterbefehl: $Arg1"; Usage }
        }
    }

    default { Write-Error "Unbekannter Befehl: $Command"; Usage }
}
