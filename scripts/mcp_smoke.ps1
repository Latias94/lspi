param(
  [Parameter(Mandatory = $false)]
  [string]$WorkspaceRoot = ".",

  [Parameter(Mandatory = $false)]
  [string]$ConfigPath = "",

  [Parameter(Mandatory = $false)]
  [int]$TimeoutSeconds = 120
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

Write-Host "Building lspi (debug)..." -ForegroundColor Cyan
& cargo build -p lspi | Out-Host

$exe = Join-Path -Path (Get-Location) -ChildPath "target\debug\lspi.exe"
if (-not (Test-Path $exe)) {
  throw "missing binary: $exe"
}

$resolvedWorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path

$args = @("mcp", "--workspace-root", $WorkspaceRoot)
if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
  $args += @("--config", $ConfigPath)
}

Write-Host "Running doctor..." -ForegroundColor Cyan
& $exe doctor --workspace-root $WorkspaceRoot @(
  if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { @("--config", $ConfigPath) } else { @() }
) | Out-Host

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
$stderr = $p.StandardError

try {
  Write-Host "Initializing..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 1
    method = "initialize"
    params = @{
      protocolVersion = "2025-03-26"
      capabilities = @{}
      clientInfo = @{ name = "lspi-smoke"; version = "0.0.0" }
    }
  }
  $initResp = Read-ResponseById $stdout 1 $TimeoutSeconds
  Assert-NoJsonRpcError $initResp "initialize"
  Write-Host ("initialize => " + ($initResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray

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
  Write-Host ("tools/list => " + ($toolsResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray

  $mainPath = Join-Path -Path (Resolve-Path $WorkspaceRoot) -ChildPath "crates\lspi\src\main.rs"
  $pos = Find-Position1Based $mainPath "run_stdio_with_options"
  Write-Host "Using position for run_stdio_with_options: line=$($pos.line) character=$($pos.character)" -ForegroundColor DarkGray

  Write-Host "tools/call find_definition (by name) ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 3
    method = "tools/call"
    params = @{
      name = "find_definition"
      arguments = @{
        file_path = "crates/lspi-mcp/src/lib.rs"
        symbol_name = "run_stdio_with_options"
      }
    }
  }
  $defResp = Read-ResponseById $stdout 3 $TimeoutSeconds
  Assert-NoJsonRpcError $defResp "find_definition"
  Assert-ToolOk $defResp "find_definition"
  Write-Host ("find_definition => " + ($defResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray
  $scDef = Get-ToolStructuredContent $defResp
  $defFiles = @()
  foreach ($m in $scDef.results) { foreach ($d in $m.definitions) { $defFiles += $d.file_path } }
  if ($scDef.definition_locations -lt 1) { throw "find_definition expected definition_locations >= 1" }
  Assert-ContainsWorkspacePath $defFiles $resolvedWorkspaceRoot "find_definition"
  Assert-ContainsSubpath $defFiles "crates/lspi-mcp/src/lib.rs" "find_definition"

  Write-Host "tools/call find_definition_at ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 4
    method = "tools/call"
    params = @{
      name = "find_definition_at"
      arguments = @{
        file_path = "crates/lspi/src/main.rs"
        line = $pos.line
        character = $pos.character
      }
    }
  }
  $defAtResp = Read-ResponseById $stdout 4 $TimeoutSeconds
  Assert-NoJsonRpcError $defAtResp "find_definition_at"
  Assert-ToolOk $defAtResp "find_definition_at"
  Write-Host ("find_definition_at => " + ($defAtResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray
  $scDefAt = Get-ToolStructuredContent $defAtResp
  $defAtFiles = @()
  foreach ($d in $scDefAt.definitions) { $defAtFiles += $d.file_path }
  if ($scDefAt.definition_locations -lt 1) { throw "find_definition_at expected definition_locations >= 1" }
  Assert-ContainsWorkspacePath $defAtFiles $resolvedWorkspaceRoot "find_definition_at"
  Assert-ContainsSubpath $defAtFiles "crates/lspi-mcp/src/lib.rs" "find_definition_at"

  Write-Host "tools/call find_references (by name) ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 5
    method = "tools/call"
    params = @{
      name = "find_references"
      arguments = @{
        file_path = "crates/lspi-mcp/src/lib.rs"
        symbol_name = "run_stdio_with_options"
        max_results = 200
      }
    }
  }
  $refsResp = Read-ResponseById $stdout 5 $TimeoutSeconds
  Assert-NoJsonRpcError $refsResp "find_references"
  Assert-ToolOk $refsResp "find_references"
  Write-Host ("find_references => " + ($refsResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray
  $scRefs = Get-ToolStructuredContent $refsResp
  $refFiles = @()
  foreach ($m in $scRefs.results) { foreach ($r in $m.references) { $refFiles += $r.file_path } }
  if ($scRefs.reference_locations -lt 1) { throw "find_references expected reference_locations >= 1" }
  Assert-ContainsWorkspacePath $refFiles $resolvedWorkspaceRoot "find_references"
  Assert-ContainsSubpath $refFiles "crates/lspi/src/main.rs" "find_references"

  Write-Host "tools/call find_references_at ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 6
    method = "tools/call"
    params = @{
      name = "find_references_at"
      arguments = @{
        file_path = "crates/lspi/src/main.rs"
        line = $pos.line
        character = $pos.character
        max_results = 200
      }
    }
  }
  $refsAtResp = Read-ResponseById $stdout 6 $TimeoutSeconds
  Assert-NoJsonRpcError $refsAtResp "find_references_at"
  Assert-ToolOk $refsAtResp "find_references_at"
  Write-Host ("find_references_at => " + ($refsAtResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray
  $scRefsAt = Get-ToolStructuredContent $refsAtResp
  $refsAtFiles = @()
  foreach ($r in $scRefsAt.references) { $refsAtFiles += $r.file_path }
  if ($scRefsAt.reference_locations -lt 1) { throw "find_references_at expected reference_locations >= 1" }
  Assert-ContainsWorkspacePath $refsAtFiles $resolvedWorkspaceRoot "find_references_at"
  Assert-ContainsSubpath $refsAtFiles "crates/lspi/src/main.rs" "find_references_at"
  Assert-ContainsSubpath $refsAtFiles "crates/lspi-mcp/src/lib.rs" "find_references_at"

  Write-Host "tools/call rename_symbol_strict (dry_run=true) ..." -ForegroundColor Cyan
  $mainHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $mainPath).Hash
  $mcpLibPath = Join-Path -Path (Resolve-Path $WorkspaceRoot) -ChildPath "crates\lspi-mcp\src\lib.rs"
  $mcpLibHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $mcpLibPath).Hash
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 7
    method = "tools/call"
    params = @{
      name = "rename_symbol_strict"
      arguments = @{
        file_path = "crates/lspi/src/main.rs"
        line = $pos.line
        character = $pos.character
        new_name = "run_stdio_with_options_tmp"
        dry_run = $true
      }
    }
  }
  $renameResp = Read-ResponseById $stdout 7 $TimeoutSeconds
  Assert-NoJsonRpcError $renameResp "rename_symbol_strict"
  $scRename = Get-ToolStructuredContent $renameResp
  if ($null -eq $scRename -or $scRename.ok -ne $true) {
    $payload = $renameResp | ConvertTo-Json -Compress -Depth 10
    throw "rename_symbol_strict returned ok=false: $payload"
  }
  if ($scRename.dry_run -ne $true) {
    throw "rename_symbol_strict expected dry_run=true"
  }
  $mainHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $mainPath).Hash
  if ($mainHashAfter -ne $mainHashBefore) {
    throw "rename_symbol_strict(dry_run) modified file unexpectedly: $mainPath"
  }
  $mcpLibHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $mcpLibPath).Hash
  if ($mcpLibHashAfter -ne $mcpLibHashBefore) {
    throw "rename_symbol_strict(dry_run) modified file unexpectedly: $mcpLibPath"
  }
  if ($null -eq $scRename.edit -or $null -eq $scRename.edit.files -or $scRename.edit.files.Count -lt 1) {
    throw "rename_symbol_strict expected non-empty preview edit"
  }
  $editFiles = @()
  foreach ($f in $scRename.edit.files) { $editFiles += $f.file_path }
  Assert-ContainsSubpath $editFiles "crates/lspi/src/main.rs" "rename_symbol_strict"
  Assert-ContainsSubpath $editFiles "crates/lspi-mcp/src/lib.rs" "rename_symbol_strict"
  Write-Host ("rename_symbol_strict => " + ($renameResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray

  Write-Host "tools/call get_diagnostics ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 8
    method = "tools/call"
    params = @{
      name = "get_diagnostics"
      arguments = @{
        file_path = "crates/lspi/src/main.rs"
        max_results = 200
      }
    }
  }
  $diagResp = Read-ResponseById $stdout 8 $TimeoutSeconds
  Assert-NoJsonRpcError $diagResp "get_diagnostics"
  Assert-ToolOk $diagResp "get_diagnostics"
  Write-Host ("get_diagnostics => " + ($diagResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray

  Write-Host "tools/call hover_at ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 9
    method = "tools/call"
    params = @{
      name = "hover_at"
      arguments = @{
        file_path = "crates/lspi/src/main.rs"
        line = $pos.line
        character = $pos.character
      }
    }
  }
  $hoverResp = Read-ResponseById $stdout 9 $TimeoutSeconds
  Assert-NoJsonRpcError $hoverResp "hover_at"
  Assert-ToolOk $hoverResp "hover_at"
  Write-Host ("hover_at => " + ($hoverResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray

  Write-Host "tools/call get_document_symbols ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 10
    method = "tools/call"
    params = @{
      name = "get_document_symbols"
      arguments = @{
        file_path = "crates/lspi/src/main.rs"
        max_results = 2000
      }
    }
  }
  $symResp = Read-ResponseById $stdout 10 $TimeoutSeconds
  Assert-NoJsonRpcError $symResp "get_document_symbols"
  Assert-ToolOk $symResp "get_document_symbols"
  Write-Host ("get_document_symbols => " + ($symResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray
  $scSyms = Get-ToolStructuredContent $symResp
  if ($null -eq $scSyms.symbol_count -or $scSyms.symbol_count -lt 1) { throw "get_document_symbols expected symbol_count >= 1" }

  Write-Host "tools/call search_workspace_symbols ..." -ForegroundColor Cyan
  Write-JsonLine $stdin @{
    jsonrpc = "2.0"
    id = 11
    method = "tools/call"
    params = @{
      name = "search_workspace_symbols"
      arguments = @{
        query = "run_stdio_with_options"
        max_results = 50
        file_path = "crates/lspi/src/main.rs"
      }
    }
  }
  $wsSymResp = Read-ResponseById $stdout 11 $TimeoutSeconds
  Assert-NoJsonRpcError $wsSymResp "search_workspace_symbols"
  Assert-ToolOk $wsSymResp "search_workspace_symbols"
  Write-Host ("search_workspace_symbols => " + ($wsSymResp | ConvertTo-Json -Compress -Depth 10)) -ForegroundColor DarkGray

  Write-Host "OK" -ForegroundColor Green
} finally {
  try { $stdin.Close() } catch {}
  try {
    if (-not $p.HasExited) {
      $p.WaitForExit(2000) | Out-Null
    }
  } catch {}
  if (-not $p.HasExited) {
    $p.Kill()
  }
  $err = ""
  try { $err = $stderr.ReadToEnd() } catch {}
  if (-not [string]::IsNullOrWhiteSpace($err)) {
    Write-Host "Server stderr (for debugging):" -ForegroundColor Yellow
    Write-Host $err
  }
}
