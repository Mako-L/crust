# MCP Gateway

Crust can wrap any [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server as a transparent stdio proxy — intercepting `tools/call` and `resources/read` requests before they reach the server.

```bash
crust mcp-gateway -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir
```

## How It Works

```text
MCP Client (Claude Desktop, IDE, etc.)
  │ stdin/stdout (JSON-RPC 2.0)
  ▼
┌──────────────────────────────────────┐
│         crust mcp-gateway            │
│                                      │
│  Client→Server: inspect each request │
│    ├─ tools/call      → Evaluate     │
│    ├─ resources/read  → Evaluate     │
│    └─ everything else → pass         │
│                                      │
│  BLOCKED → JSON-RPC error to client  │
│  ALLOWED → forward to server         │
└──────────────────────────────────────┘
  │ stdin/stdout
  ▼
Real MCP Server (filesystem, database, etc.)
```

Crust evaluates every `tools/call` and `resources/read` request against the rule engine. Tool arguments (paths, commands, content) are extracted using **shape-based detection** — any tool with a `path` field is treated as file access, regardless of the tool name. This means Crust protects against novel tools without needing explicit configuration.

Allowed requests pass through byte-for-byte unchanged. Blocked requests receive a JSON-RPC error response with code `-32001` and a `[Crust]`-prefixed message explaining the block.

## Prerequisites

1. **Crust** installed and on your `PATH`
2. **An MCP server** — any server that speaks [MCP](https://modelcontextprotocol.io) over stdio

## Supported MCP Servers

Any MCP server works. Common examples:

| Server | Install | Command |
|--------|---------|---------|
| [Filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | `npm i -g @modelcontextprotocol/server-filesystem` | `npx @modelcontextprotocol/server-filesystem /path` |
| [Everything](https://github.com/modelcontextprotocol/servers/tree/main/src/everything) | `npm i -g @modelcontextprotocol/server-everything` | `npx @modelcontextprotocol/server-everything` |
| [PostgreSQL](https://github.com/modelcontextprotocol/servers/tree/main/src/postgres) | `npm i -g @modelcontextprotocol/server-postgres` | `npx @modelcontextprotocol/server-postgres $DATABASE_URL` |
| Custom server | — | Any command that speaks MCP over stdio |

## Claude Desktop

Add Crust as a wrapper in your Claude Desktop MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "crust",
      "args": ["mcp-gateway", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"]
    }
  }
}
```

## Auto-detect Mode

If you don't know whether a subprocess speaks MCP or ACP, use `crust wrap`:

```bash
crust wrap -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir
```

This inspects both MCP (inbound) and ACP (outbound) methods simultaneously. Since the method names are disjoint, there is no conflict.

## What Gets Blocked

The same rules apply as the HTTP gateway and ACP modes. Security-relevant tool calls are evaluated against path rules, DLP patterns, and content matching:

| Scenario | Result |
|----------|--------|
| `tools/call read_text_file /app/main.go` | Allowed |
| `tools/call read_text_file /app/.env` | Blocked — `.env` files contain secrets |
| `tools/call write_file /app/.env` | Blocked — cannot write to `.env` |
| `tools/call read_text_file ~/.ssh/id_rsa` | Blocked — SSH private keys |
| `resources/read file:///etc/shadow` | Blocked — system auth files |
| `tools/call list_directory /app/src` | Allowed |
| `initialize`, `tools/list`, notifications | Passed through unchanged |

## CLI Reference

```bash
crust mcp-gateway [flags] -- <mcp-server-command> [args...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.crust/config.yaml` | Path to configuration file |
| `--rules-dir` | `~/.crust/rules/` | Directory for custom rules |
| `--log-level` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `--disable-builtin` | `false` | Disable built-in security rules |

Logs go to stderr so they don't interfere with the JSON-RPC stdio stream.
