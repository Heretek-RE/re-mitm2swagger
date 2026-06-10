"""MCP server entry point for re-mitm2swagger."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from re_mitm2swagger import proxy

logger = logging.getLogger("re_mitm2swagger")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-mitm2swagger")


@mcp.tool()
def check_mitm() -> dict:
    """Confirm mitmdump is on PATH."""
    import shutil

    p = shutil.which("mitmdump")
    return {
        "mitmdump": p or "NOT FOUND",
        "status": "OK" if p else "WARN",
    }


@mcp.tool()
def start_capture(
    port: int = 8080,
    output_path: str = "",
    mode: str = "regular",
) -> dict:
    """Spawn mitmdump in the background, writing flows to *output_path*.

    Args:
        port: listen port (default 8080)
        output_path: where to write the flow file (default: ./re-ai-capture.flow)
        mode: "regular" (default, set https_proxy=...), "transparent",
            or "socks5"
    """
    return proxy.start_capture(port, output_path, mode)


@mcp.tool()
def stop_capture(pid: int) -> dict:
    """Stop a previously-started mitmdump process by PID."""
    return proxy.stop_capture(pid)


@mcp.tool()
def parse_flows(path: str) -> dict:
    """Read a mitmproxy flow file and return a summary list."""
    return proxy.parse_flows(path)


@mcp.tool()
def har_to_swagger(path: str, output_path: str = "") -> dict:
    """Convert a HAR file to an OpenAPI 3.0 spec.

    Performs path templating (digits → {id}, UUIDs → {uuid}).
    """
    return proxy.har_to_swagger(path, output_path)


@mcp.tool()
def flow_to_swagger(path: str, output_path: str = "") -> dict:
    """Run mitmproxy2swagger on a flow file → OAS spec."""
    return proxy.flow_to_swagger(path, output_path)


@mcp.tool()
def filter_flows(
    path: str,
    method: str = "",
    host: str = "",
    path_substring: str = "",
    status: int = 0,
    content_type: str = "",
) -> dict:
    """Filter parsed flows by method, host, path substring, status, content-type."""
    return proxy.filter_flows(
        path,
        method=method,
        host=host,
        path_substring=path_substring,
        status=status,
        content_type=content_type,
    )


@mcp.tool()
def extract_secrets(path: str) -> dict:
    """Heuristically find tokens, JWTs, API keys in flow headers/URLs."""
    return proxy.extract_secrets(path)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
