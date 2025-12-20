param(
  [Parameter(Mandatory = $true)]
  [string]$ExtensionId,

  [Parameter(Mandatory = $false)]
  [string]$PersonaPath
)

$ErrorActionPreference = "Stop"

$HostName = "com.persona.native"

function Fail($Message) {
  Write-Error $Message
  exit 1
}

function Find-Persona {
  if ($PersonaPath -and (Test-Path $PersonaPath)) {
    return (Resolve-Path $PersonaPath).Path
  }

  $cmd = Get-Command persona -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.Path) {
    return (Resolve-Path $cmd.Path).Path
  }

  $candidates = @(
    "$env:USERPROFILE\.cargo\bin\persona.exe",
    "$env:ProgramFiles\Persona\persona.exe",
    "$env:LOCALAPPDATA\Programs\Persona\persona.exe"
  )

  foreach ($path in $candidates) {
    if (Test-Path $path) {
      return (Resolve-Path $path).Path
    }
  }

  Fail "Could not find persona.exe. Install it and ensure it's on PATH, or pass -PersonaPath."
}

function Ensure-Bridge($PersonaExe) {
  $p = Start-Process -FilePath $PersonaExe -ArgumentList @("bridge", "--help") -NoNewWindow -PassThru -Wait
  if ($p.ExitCode -ne 0) {
    Fail "persona.exe does not support the 'bridge' command. Please update Persona."
  }
}

function Write-Manifest($ManifestPath, $BridgeExePath) {
  $allowedOrigins = @("chrome-extension://$ExtensionId/")
  $manifest = @{
    name = $HostName
    description = "Persona Password Manager Native Messaging Bridge"
    path = $BridgeExePath
    type = "stdio"
    allowed_origins = $allowedOrigins
  } | ConvertTo-Json -Depth 4

  $dir = Split-Path $ManifestPath -Parent
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Set-Content -Path $ManifestPath -Value $manifest -Encoding UTF8
}

function Set-RegistryHost($RootKey) {
  $keyPath = "HKCU:\Software\$RootKey\NativeMessagingHosts\$HostName"
  New-Item -Path $keyPath -Force | Out-Null
  New-ItemProperty -Path $keyPath -Name "" -Value $ManifestPath -PropertyType String -Force | Out-Null
}

if (-not $ExtensionId.Trim()) {
  Fail "ExtensionId is required (find it at chrome://extensions)."
}

$personaExe = Find-Persona
Write-Host "Found persona: $personaExe"
Ensure-Bridge $personaExe

$installDir = Join-Path $env:LOCALAPPDATA "Persona\native-messaging"
$bridgeExe = Join-Path $installDir "persona-bridge.exe"
$ManifestPath = Join-Path $installDir "$HostName.json"

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item -Path $personaExe -Destination $bridgeExe -Force

Write-Manifest -ManifestPath $ManifestPath -BridgeExePath $bridgeExe

# Chrome, Edge, Brave, Chromium
Set-RegistryHost -RootKey "Google\Chrome"
Set-RegistryHost -RootKey "Microsoft\Edge"
Set-RegistryHost -RootKey "BraveSoftware\Brave-Browser"
Set-RegistryHost -RootKey "Chromium"

Write-Host ""
Write-Host "Native messaging host installed:"
Write-Host "  Manifest: $ManifestPath"
Write-Host "  Host exe: $bridgeExe"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Install the Persona extension"
Write-Host "  2. Open the extension popup → Pairing"
