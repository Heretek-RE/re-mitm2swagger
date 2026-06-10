# re-mitm2swagger

MCP server exposing mitmproxy + mitmproxy2swagger for REST API reverse-engineering from HTTP captures.

Version: 0.1.0 | License: MIT

## Structure

```
re-mitm2swagger/
  pyproject.toml                    # build config (setuptools, mcp[cli] + deps)
  src/re_mitm2swagger/
    __init__.py
    __main__.py                     # entry: from server import main; main()
    server.py                       # FastMCP app with @mcp.tool() functions
  README.md
  LICENSE
  SECURITY.md


```

## Build

```bash
pip install -e .                    # install with deps
re-mitm2swagger                         # start MCP server on stdio
```



## Tools

This server exposes these MCP tools: `check_mitm,start_capture,stop_capture,parse_flows,har_to_swagger,flow_to_swagger,filter_flows,extract_secrets`

## Usage (standalone)

Register this server in your `.mcp.json`:

```json
{
  "mcpServers": {
    "re-mitm2swagger": {
      "command": "uv",
      "args": ["--directory", "/path/to/re-mitm2swagger", "run", "re-mitm2swagger"]
    }
  }
}
```

Or use via the [RE-AI agent-space](https://github.com/Heretek-RE/RE-AI): `./install.sh` clones all servers at pinned versions.
