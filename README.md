# re-mitm2swagger

MCP server for REST API reverse engineering from HTTP traffic captures. Wraps [mitmproxy](https://mitmproxy.org/) for live capture and [mitmproxy2swagger](https://github.com/alufers/mitmproxy2swagger) for spec derivation.

## Tools

| Tool | What it does |
|---|---|
| `check_mitm` | Confirm mitmdump is on PATH |
| `start_capture` | Spawn mitmdump in the background |
| `stop_capture` | Stop a previously-started capture |
| `parse_flows` | Read a mitmproxy flow file |
| `har_to_swagger` | Convert HAR → OpenAPI 3.0 spec (with path templating) |
| `flow_to_swagger` | mitmproxy2swagger on a flow file → OAS |
| `filter_flows` | Filter flows by method/host/path/status/content-type |
| `extract_secrets` | Heuristically find tokens, JWTs, API keys |

## Install

```bash
pip install mitmproxy mitmproxy2swagger
pip install -e ./servers/re-mitm2swagger
```

## Why this matters

Most mobile apps and SPAs talk to a REST API. The fastest way to understand the API surface is to capture traffic, then derive the spec. mitmproxy handles the capture, mitmproxy2swagger handles the spec — this server glues them together with secrets detection and filtering.
