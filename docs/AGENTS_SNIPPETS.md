# Agent Prompt Snippets (for Codex/Claude Code/etc.)

This document provides copy-paste prompt snippets you can add to your project's `AGENTS.md` (or your agent's system prompt) so the assistant knows when and how to use `lspi`.

## lspi (LSP semantic navigation / symbol refactoring)

- Purpose: Provide symbol-level navigation and safe refactoring via LSP through `lspi` (MCP server).
- When to use:
  - Jump to definitions / implementations
  - Find references across the workspace
  - Rename symbols safely across multiple files
  - Inspect diagnostics before/after changes
- Workflow:
  1) Identify the target symbol (name + file, or file + position)
  2) Use definition/references to confirm the correct symbol
  3) Preview rename first (`dry_run=true`), then apply if safe
  4) Summarize changes (files, locations, reason) for traceability
- Tools:
  - `find_definition`, `find_definition_at`
  - `find_references`, `find_references_at`
  - `rename_symbol`, `rename_symbol_strict`
  - `get_diagnostics`
  - `restart_server` / `stop_server` (if the language server is stuck or you need to release resources)
- Strategy:
  - Prefer small, precise operations and verify with references/diagnostics.
  - Avoid large multi-file rewrites unless required.
  - Always preview edits before applying.

### Copy-paste snippet (Chinese)

You can paste the following into your project's `AGENTS.md`:

```md
## lspi（代码语义检索 / 符号级编辑）

- 用途：通过 `lspi`（MCP + LSP）提供符号级检索、引用分析与安全重命名，帮助在大型代码库中高效定位、理解并修改代码。
- 触发：需要按符号/语义查找、跨文件引用分析、重构迁移、诊断检查、在指定符号处进行安全改动等场景。
- 流程：确认目标文件/位置 → definition/references 验证上下文 → rename 先预览(dry_run=true) → 必要时再 apply(dry_run=false) → 汇总变更与原因。
- 常用工具：
  - find_definition / find_definition_at
  - find_references / find_references_at
  - rename_symbol / rename_symbol_strict
  - get_diagnostics
  - restart_server / stop_server
- 使用策略：优先小范围、精准操作；先验证再改动；输出需带文件/符号/位置与变更原因，便于追溯。
```
