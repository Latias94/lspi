param(
  [Parameter(Mandatory = $false)]
  [string]$WorkspaceRoot = "",

  # Optional: path to a .sln or .csproj file (preferred for real projects)
  [Parameter(Mandatory = $false)]
  [string]$ProjectPath = "",

  [Parameter(Mandatory = $false)]
  [int]$TimeoutSeconds = 180,

  [Parameter(Mandatory = $false)]
  [switch]$SkipIfMissing = $true,

  # Optional: file (relative to workspace root) used for position-based calls.
  # If omitted, the script will try to auto-pick a .cs file under the project root.
  [Parameter(Mandatory = $false)]
  [string]$TestFile = "",

  # Optional: the needle string to locate the position for definition/references/rename.
  # If omitted or not found, those position-based steps may be skipped unless -Strict is set.
  [Parameter(Mandatory = $false)]
  [string]$Needle = "",

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

function Assert-ContainsSubpath($paths, $subpath, $label) {
  $needle = Normalize-PathString $subpath
  foreach ($p in $paths) {
    $np = Normalize-PathString ([string]$p)
    if ($np.Contains($needle)) {
      return
    }
  }
  throw "${label}: expected at least one path containing: $subpath"
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

function Resolve-ProjectRoot($workspaceRoot, $projectPath) {
  if (-not [string]::IsNullOrWhiteSpace($workspaceRoot)) {
    return (Resolve-Path -LiteralPath $workspaceRoot).Path
  }

  if (-not [string]::IsNullOrWhiteSpace($projectPath)) {
    $pp = (Resolve-Path -LiteralPath $projectPath).Path
    if (Test-Path -LiteralPath $pp -PathType Leaf) {
      return (Split-Path -Parent $pp)
    }
    if (Test-Path -LiteralPath $pp -PathType Container) {
      return $pp
    }
    throw "invalid ProjectPath: $projectPath"
  }

  return (Resolve-Path -LiteralPath "samples/csharp/Hello").Path
}

function Pick-ProjectFile($projectRoot) {
  $sln = Get-ChildItem -LiteralPath $projectRoot -Filter *.sln -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $sln) { return $sln.FullName }
  $csproj = Get-ChildItem -LiteralPath $projectRoot -Filter *.csproj -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $csproj) { return $csproj.FullName }
  return $null
}

function Pick-CsFile($projectRoot) {
  $files = Get-ChildItem -LiteralPath $projectRoot -Recurse -Filter *.cs -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\\\(bin|obj)\\\\' } |
    Select-Object -First 1
  if ($null -ne $files) { return $files.FullName }
  return $null
}

Write-Host "Checking prerequisites..." -ForegroundColor Cyan
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
  Should-Skip "dotnet is not available on PATH"
}
if (-not (Get-Command omnisharp -ErrorAction SilentlyContinue)) {
  Should-Skip "omnisharp is not available on PATH (set LSPI_OMNISHARP_COMMAND or install OmniSharp)"
}

Write-Host "Building lspi (debug)..." -ForegroundColor Cyan
& cargo build -p lspi | Out-Host

$exe = Join-Path -Path (Get-Location) -ChildPath "target\debug\lspi.exe"
if (-not (Test-Path $exe)) {
  throw "missing binary: $exe"
}

$resolvedWorkspaceRoot = Resolve-ProjectRoot $WorkspaceRoot $ProjectPath
$projectFile = $null
if (-not [string]::IsNullOrWhiteSpace($ProjectPath)) {
  $projectFile = (Resolve-Path -LiteralPath $ProjectPath).Path
} else {
  $projectFile = Pick-ProjectFile $resolvedWorkspaceRoot
}

if ($null -ne $projectFile) {
  Write-Host "Project file: $projectFile" -ForegroundColor DarkGray
} else {
  Write-Host "Project file: <not found> (continuing best-effort)" -ForegroundColor DarkGray
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
  $testFileFull = Pick-CsFile $resolvedWorkspaceRoot
  if ($null -eq $testFileFull) {
    if ($Strict) { throw "no .cs files found under: $resolvedWorkspaceRoot" }
    Should-Skip "no .cs files found under: $resolvedWorkspaceRoot"
  }
}

$tmpConfig = Join-Path -Path $env:TEMP -ChildPath ("lspi-csharp-config-" + [Guid]::NewGuid().ToString("N") + ".toml")
@"
[[servers]]
id = "omnisharp"
kind = "omnisharp"
extensions = ["cs"]
root_dir = "."
args = ["-lsp"]
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
      clientInfo = @{ name = "lspi-smoke-csharp"; version = "0.0.0" }
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

  $testFileRel = (Resolve-Path -LiteralPath $testFileFull).Path.Substring($resolvedWorkspaceRoot.Length).TrimStart('\','/')
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
          new_name = "RenamedSymbolTmp"
          dry_run = $true
        }
      }
    }
    $renameResp = Read-ResponseById $stdout 5 $TimeoutSeconds
    Assert-NoJsonRpcError $renameResp "rename_symbol_strict"
    Assert-ToolOk $renameResp "rename_symbol_strict"
  }

  Write-Host "tools/call get_diagnostics ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 6
    method = "tools/call"
    params = @{
      name = "get_diagnostics"
      arguments = @{
        file_path = $testFileRel
        max_results = 200
      }
    }
  }
  $diagResp = Read-ResponseById $stdout 6 $TimeoutSeconds
  Assert-NoJsonRpcError $diagResp "get_diagnostics"
  Assert-ToolOk $diagResp "get_diagnostics"

  Write-Host "tools/call restart_server (extensions=['cs']) ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 7
    method = "tools/call"
    params = @{
      name = "restart_server"
      arguments = @{
        extensions = @("cs")
      }
    }
  }
  $restartResp = Read-ResponseById $stdout 7 $TimeoutSeconds
  Assert-NoJsonRpcError $restartResp "restart_server"
  $scRestart = Get-ToolStructuredContent $restartResp
  if ($null -eq $scRestart) { throw "restart_server missing structuredContent" }
  if ($scRestart.ok -ne $true) {
    $payload = $restartResp | ConvertTo-Json -Compress -Depth 10
    throw "restart_server returned ok=false: $payload"
  }

  Write-Host "tools/call get_document_symbols ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 8
    method = "tools/call"
    params = @{
      name = "get_document_symbols"
      arguments = @{
        file_path = $testFileRel
        max_results = 2000
      }
    }
  }
  $symResp = Read-ResponseById $stdout 8 $TimeoutSeconds
  Assert-NoJsonRpcError $symResp "get_document_symbols"
  Assert-ToolOk $symResp "get_document_symbols"

  if ($posOk) {
    Write-Host "tools/call hover_at ..." -ForegroundColor Cyan
    Write-JsonLine $stdin @{
      jsonrpc = "2.0"
      id = 9
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
    $hoverResp = Read-ResponseById $stdout 9 $TimeoutSeconds
    Assert-NoJsonRpcError $hoverResp "hover_at"
    Assert-ToolOk $hoverResp "hover_at"

    Write-Host "tools/call find_incoming_calls_at ..." -ForegroundColor Cyan
    Write-JsonLine $stdin @{
      jsonrpc = "2.0"
      id = 10
      method = "tools/call"
      params = @{
        name = "find_incoming_calls_at"
        arguments = @{
          file_path = $testFileRel
          line = $pos.line
          character = $pos.character
          max_results = 50
        }
      }
    }
    $inCallsResp = Read-ResponseById $stdout 10 $TimeoutSeconds
    Assert-NoJsonRpcError $inCallsResp "find_incoming_calls_at"
    Assert-ToolOk $inCallsResp "find_incoming_calls_at"

    Write-Host "tools/call find_outgoing_calls_at ..." -ForegroundColor Cyan
    Write-JsonLine $stdin @{
      jsonrpc = "2.0"
      id = 11
      method = "tools/call"
      params = @{
        name = "find_outgoing_calls_at"
        arguments = @{
          file_path = $testFileRel
          line = $pos.line
          character = $pos.character
          max_results = 50
        }
      }
    }
    $outCallsResp = Read-ResponseById $stdout 11 $TimeoutSeconds
    Assert-NoJsonRpcError $outCallsResp "find_outgoing_calls_at"
    Assert-ToolOk $outCallsResp "find_outgoing_calls_at"
  }

  Write-Host "OK" -ForegroundColor Green
} finally {
  if (Test-Path $tmpConfig) { Remove-Item -LiteralPath $tmpConfig -Force -ErrorAction SilentlyContinue }
}
