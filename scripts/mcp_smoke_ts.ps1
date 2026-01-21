param(
  # Workspace root (project root). If omitted, defaults to samples/typescript/Hello.
  [Parameter(Mandatory = $false)]
  [string]$WorkspaceRoot = "",

  # Optional: file (relative to workspace root) used for position-based calls.
  [Parameter(Mandatory = $false)]
  [string]$TestFile = "",

  # Optional: needle string to locate position for definition/references/rename.
  [Parameter(Mandatory = $false)]
  [string]$Needle = "add(",

  # If set, attempt to install Node deps (npm install) when node_modules is missing.
  [Parameter(Mandatory = $false)]
  [switch]$InstallDeps = $false,

  # Optional: override the language server command/args (default: typescript-language-server --stdio).
  [Parameter(Mandatory = $false)]
  [string]$LspCommand = "typescript-language-server",

  [Parameter(Mandatory = $false)]
  [string[]]$LspArgs = @("--stdio"),

  [Parameter(Mandatory = $false)]
  [int]$TimeoutSeconds = 180,

  [Parameter(Mandatory = $false)]
  [switch]$SkipIfMissing = $true,

  # If set, missing TestFile/Needle will fail instead of skipping.
  [Parameter(Mandatory = $false)]
  [switch]$Strict = $false
)

$ErrorActionPreference = "Stop"

function Write-JsonLine($writer, $obj) {
  $line = $obj | ConvertTo-Json -Compress -Depth 32
  $writer.WriteLine($line)
  $writer.Flush()
}

function Read-ResponseById($reader, $id, $timeoutSeconds) {
  $deadline = (Get-Date).AddSeconds($timeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    if ($reader.EndOfStream) {
      throw "server stdout closed before receiving response id=$id"
    }
    $line = $reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) {
      continue
    }
    try {
      $msg = $line | ConvertFrom-Json -ErrorAction Stop
    } catch {
      continue
    }
    if ($null -ne $msg.id -and $msg.id -eq $id) {
      return $msg
    }
  }
  throw "timeout waiting for response id=$id"
}

function Assert-NoJsonRpcError($resp, $label) {
  if ($null -ne $resp.error) {
    $payload = $resp | ConvertTo-Json -Compress -Depth 10
    throw "$label returned JSON-RPC error: $payload"
  }
}

function Get-ToolStructuredContent($resp) {
  if ($null -eq $resp.result) { return $null }
  if ($null -ne $resp.result.structuredContent) { return $resp.result.structuredContent }
  return $null
}

function Assert-ToolOk($resp, $tool) {
  $sc = Get-ToolStructuredContent $resp
  if ($null -eq $sc) {
    $payload = $resp | ConvertTo-Json -Compress -Depth 10
    throw "$tool missing structuredContent: $payload"
  }
  if ($null -eq $sc.ok -or $sc.ok -ne $true) {
    $payload = $resp | ConvertTo-Json -Compress -Depth 10
    throw "$tool returned ok=false: $payload"
  }
  if ($null -ne $sc.tool -and $sc.tool -ne $tool) {
    throw "$tool returned mismatched tool field: got=$($sc.tool)"
  }
}

function Normalize-PathString($p) {
  if ([string]::IsNullOrWhiteSpace($p)) { return "" }
  $s = $p.Replace("/", "\")
  return $s.Trim().ToLowerInvariant()
}

function Assert-ContainsWorkspacePath($paths, $workspaceRoot, $label) {
  $root = Normalize-PathString $workspaceRoot
  foreach ($p in $paths) {
    $np = Normalize-PathString ([string]$p)
    if ($np.StartsWith($root)) {
      return
    }
  }
  throw "${label}: expected at least one path under workspace root: $workspaceRoot"
}

function Find-Position1Based($filePath, $needle) {
  $lines = Get-Content -LiteralPath $filePath
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $idx = $lines[$i].IndexOf($needle)
    if ($idx -ge 0) {
      return @{
        line = $i + 1
        character = $idx + 1
      }
    }
  }
  throw "needle not found in ${filePath}: $needle"
}

function Should-Skip($reason) {
  if ($SkipIfMissing) {
    Write-Host "SKIP: $reason" -ForegroundColor Yellow
    exit 0
  }
  throw $reason
}

function Escape-TomlBasicString($s) {
  if ($null -eq $s) { return "" }
  return $s.Replace("\", "\\").Replace('"', '\"')
}

function To-TomlArrayOfStrings($arr) {
  $items = @()
  foreach ($x in $arr) {
    $items += ('"' + (Escape-TomlBasicString ([string]$x)) + '"')
  }
  return "[" + ($items -join ", ") + "]"
}

function Resolve-WorkspaceRoot($workspaceRoot) {
  if (-not [string]::IsNullOrWhiteSpace($workspaceRoot)) {
    return (Resolve-Path -LiteralPath $workspaceRoot).Path
  }
  return (Resolve-Path -LiteralPath "samples/typescript/Hello").Path
}

function Pick-TsFile($projectRoot) {
  $preferred = Join-Path -Path $projectRoot -ChildPath "src\\index.ts"
  if (Test-Path -LiteralPath $preferred -PathType Leaf) { return $preferred }
  $files = Get-ChildItem -LiteralPath $projectRoot -Recurse -Filter *.ts -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\\\node_modules\\\\' } |
    Where-Object { $_.FullName -notmatch '\\\\dist\\\\' } |
    Select-Object -First 1
  if ($null -ne $files) { return $files.FullName }
  return $null
}

Write-Host "Checking prerequisites..." -ForegroundColor Cyan
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Should-Skip "node is not available on PATH"
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  Should-Skip "npm is not available on PATH"
}
$resolvedWorkspaceRoot = Resolve-WorkspaceRoot $WorkspaceRoot

if (Test-Path -LiteralPath (Join-Path $resolvedWorkspaceRoot "package.json") -PathType Leaf) {
  $nodeModules = Join-Path $resolvedWorkspaceRoot "node_modules"
  if (-not (Test-Path -LiteralPath $nodeModules -PathType Container)) {
    if ($InstallDeps) {
      Write-Host "Installing Node deps (npm install)..." -ForegroundColor Cyan
      Push-Location $resolvedWorkspaceRoot
      try {
        & npm install | Out-Host
      } finally {
        Pop-Location
      }
    } else {
      Write-Host "SKIP: node_modules missing (run npm install, or pass -InstallDeps)" -ForegroundColor Yellow
      if ($SkipIfMissing) { exit 0 } else { throw "node_modules missing under: $resolvedWorkspaceRoot" }
    }
  }
}

$lspOk = $false
if (-not [string]::IsNullOrWhiteSpace($LspCommand)) {
  if (Test-Path -LiteralPath $LspCommand -PathType Leaf) { $lspOk = $true }
  if ($null -ne (Get-Command $LspCommand -ErrorAction SilentlyContinue)) { $lspOk = $true }
}

if (-not $lspOk -and $LspCommand -eq "typescript-language-server") {
  $localCmd = Join-Path $resolvedWorkspaceRoot "node_modules\\.bin\\typescript-language-server.cmd"
  if (Test-Path -LiteralPath $localCmd -PathType Leaf) {
    $LspCommand = $localCmd
    $lspOk = $true
  } else {
    $localCmd = Join-Path $resolvedWorkspaceRoot "node_modules\\.bin\\typescript-language-server"
    if (Test-Path -LiteralPath $localCmd -PathType Leaf) {
      $LspCommand = $localCmd
      $lspOk = $true
    }
  }
}

if (-not $lspOk) {
  Should-Skip "typescript-language-server is not available (run npm install in the project, install it globally, or pass -LspCommand / -LspArgs)"
}

Write-Host "Building lspi (debug)..." -ForegroundColor Cyan
& cargo build -p lspi | Out-Host

$exe = Join-Path -Path (Get-Location) -ChildPath "target\\debug\\lspi.exe"
if (-not (Test-Path $exe)) {
  throw "missing binary: $exe"
}

$testFileFull = $null
if (-not [string]::IsNullOrWhiteSpace($TestFile)) {
  $candidate = Join-Path -Path $resolvedWorkspaceRoot -ChildPath $TestFile
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
    if ($Strict) { throw "TestFile not found: $candidate" }
    Should-Skip "TestFile not found: $candidate"
  }
  $testFileFull = (Resolve-Path -LiteralPath $candidate).Path
} else {
  $testFileFull = Pick-TsFile $resolvedWorkspaceRoot
  if ($null -eq $testFileFull) {
    if ($Strict) { throw "no .ts files found under: $resolvedWorkspaceRoot" }
    Should-Skip "no .ts files found under: $resolvedWorkspaceRoot"
  }
}

$tmpConfig = Join-Path -Path $env:TEMP -ChildPath ("lspi-ts-config-" + [Guid]::NewGuid().ToString("N") + ".toml")
$lspArgsToml = To-TomlArrayOfStrings $LspArgs
$lspCommandEscaped = Escape-TomlBasicString $LspCommand
@"
[[servers]]
id = "typescript"
kind = "generic"
extensions = ["ts", "tsx"]
language_id = "typescript"
root_dir = "."
command = "$lspCommandEscaped"
args = $lspArgsToml
initialize_timeout_ms = 20000
request_timeout_ms = 30000
warmup_timeout_ms = 0
"@ | Set-Content -LiteralPath $tmpConfig -Encoding UTF8

try {
  Write-Host "Running doctor..." -ForegroundColor Cyan
  & $exe doctor --workspace-root $resolvedWorkspaceRoot --config $tmpConfig | Out-Host

  $args = @("mcp", "--workspace-root", $resolvedWorkspaceRoot, "--config", $tmpConfig)
  Write-Host "Starting MCP server: $exe $($args -join ' ')" -ForegroundColor Cyan
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo.FileName = $exe
  $p.StartInfo.Arguments = ($args -join " ")
  $p.StartInfo.UseShellExecute = $false
  $p.StartInfo.RedirectStandardInput = $true
  $p.StartInfo.RedirectStandardOutput = $true
  $p.StartInfo.RedirectStandardError = $true
  $p.StartInfo.CreateNoWindow = $true

  [void]$p.Start()
  $stdin = $p.StandardInput
  $stdout = $p.StandardOutput

  Write-Host "Initializing..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 1
    method = "initialize"
    params = @{
      protocolVersion = "2025-03-26"
      capabilities = @{}
      clientInfo = @{ name = "lspi-smoke-ts"; version = "0.0.0" }
    }
  }
  $initResp = Read-ResponseById $stdout 1 $TimeoutSeconds
  Assert-NoJsonRpcError $initResp "initialize"

  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    method = "notifications/initialized"
    params = @{}
  }

  Write-Host "tools/list ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 2
    method = "tools/list"
    params = @{}
  }
  $toolsResp = Read-ResponseById $stdout 2 $TimeoutSeconds
  Assert-NoJsonRpcError $toolsResp "tools/list"

  $testFileRel = (Resolve-Path -LiteralPath $testFileFull).Path.Substring($resolvedWorkspaceRoot.Length).TrimStart('\', '/')
  $testFileRel = $testFileRel.Replace("\", "/")
  Write-Host "Test file: $testFileRel" -ForegroundColor DarkGray

  $pos = $null
  if (-not [string]::IsNullOrWhiteSpace($Needle)) {
    try {
      $pos = Find-Position1Based $testFileFull $Needle
      Write-Host "Using position for needle '$Needle': line=$($pos.line) character=$($pos.character)" -ForegroundColor DarkGray
    } catch {
      if ($Strict) { throw $_ }
      Write-Host "SKIP: needle not found in test file: $Needle" -ForegroundColor Yellow
      $pos = $null
    }
  } else {
    Write-Host "SKIP: Needle not provided; position-based steps will be skipped (use -Needle ...)" -ForegroundColor Yellow
  }

  if ($null -ne $pos) {
    Write-Host "tools/call find_definition_at ..." -ForegroundColor Cyan
    Write-JsonLine $stdin @{
      jsonrpc = "2.0"
      id = 3
      method = "tools/call"
      params = @{
        name = "find_definition_at"
        arguments = @{
          file_path = $testFileRel
          line = $pos.line
          character = $pos.character
        }
      }
    }
    $defAtResp = Read-ResponseById $stdout 3 $TimeoutSeconds
    Assert-NoJsonRpcError $defAtResp "find_definition_at"
    Assert-ToolOk $defAtResp "find_definition_at"
    $scDefAt = Get-ToolStructuredContent $defAtResp
    $defAtFiles = @()
    foreach ($d in $scDefAt.definitions) { $defAtFiles += $d.file_path }
    if ($scDefAt.definition_locations -lt 1) { throw "find_definition_at expected definition_locations >= 1" }
    Assert-ContainsWorkspacePath $defAtFiles $resolvedWorkspaceRoot "find_definition_at"

    Write-Host "tools/call find_references_at ..." -ForegroundColor Cyan
    Write-JsonLine $stdin @{
      jsonrpc = "2.0"
      id = 4
      method = "tools/call"
      params = @{
        name = "find_references_at"
        arguments = @{
          file_path = $testFileRel
          line = $pos.line
          character = $pos.character
          max_results = 200
        }
      }
    }
    $refsAtResp = Read-ResponseById $stdout 4 $TimeoutSeconds
    Assert-NoJsonRpcError $refsAtResp "find_references_at"
    Assert-ToolOk $refsAtResp "find_references_at"
    $scRefsAt = Get-ToolStructuredContent $refsAtResp
    $refFiles = @()
    foreach ($r in $scRefsAt.references) { $refFiles += $r.file_path }
    if ($scRefsAt.reference_locations -lt 1) { throw "find_references_at expected reference_locations >= 1" }
    Assert-ContainsWorkspacePath $refFiles $resolvedWorkspaceRoot "find_references_at"

    Write-Host "tools/call rename_symbol_strict (dry_run=true) ..." -ForegroundColor Cyan
    Write-JsonLine $stdin @{
      jsonrpc = "2.0"
      id = 5
      method = "tools/call"
      params = @{
        name = "rename_symbol_strict"
        arguments = @{
          file_path = $testFileRel
          line = $pos.line
          character = $pos.character
          new_name = "addRenamedTmp"
          dry_run = $true
        }
      }
    }
    $renameResp = Read-ResponseById $stdout 5 $TimeoutSeconds
    Assert-NoJsonRpcError $renameResp "rename_symbol_strict"
    Assert-ToolOk $renameResp "rename_symbol_strict"

    Write-Host "tools/call hover_at ..." -ForegroundColor Cyan
    Write-JsonLine $stdin @{
      jsonrpc = "2.0"
      id = 6
      method = "tools/call"
      params = @{
        name = "hover_at"
        arguments = @{
          file_path = $testFileRel
          line = $pos.line
          character = $pos.character
        }
      }
    }
    $hoverResp = Read-ResponseById $stdout 6 $TimeoutSeconds
    Assert-NoJsonRpcError $hoverResp "hover_at"
    Assert-ToolOk $hoverResp "hover_at"
  }

  Write-Host "tools/call get_document_symbols ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 7
    method = "tools/call"
    params = @{
      name = "get_document_symbols"
      arguments = @{
        file_path = $testFileRel
        max_results = 2000
      }
    }
  }
  $symResp = Read-ResponseById $stdout 7 $TimeoutSeconds
  Assert-NoJsonRpcError $symResp "get_document_symbols"
  Assert-ToolOk $symResp "get_document_symbols"

  Write-Host "tools/call get_diagnostics ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 8
    method = "tools/call"
    params = @{
      name = "get_diagnostics"
      arguments = @{
        file_path = $testFileRel
        max_results = 200
      }
    }
  }
  $diagResp = Read-ResponseById $stdout 8 $TimeoutSeconds
  Assert-NoJsonRpcError $diagResp "get_diagnostics"
  Assert-ToolOk $diagResp "get_diagnostics"

  Write-Host "tools/call restart_server (extensions=['ts']) ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 9
    method = "tools/call"
    params = @{
      name = "restart_server"
      arguments = @{
        extensions = @("ts")
      }
    }
  }
  $restartResp = Read-ResponseById $stdout 9 $TimeoutSeconds
  Assert-NoJsonRpcError $restartResp "restart_server"
  $scRestart = Get-ToolStructuredContent $restartResp
  if ($null -eq $scRestart) { throw "restart_server missing structuredContent" }
  if ($scRestart.ok -ne $true) {
    $payload = $restartResp | ConvertTo-Json -Compress -Depth 10
    throw "restart_server returned ok=false: $payload"
  }

  Write-Host "OK" -ForegroundColor Green
} finally {
  if (Test-Path $tmpConfig) { Remove-Item -LiteralPath $tmpConfig -Force -ErrorAction SilentlyContinue }
}
