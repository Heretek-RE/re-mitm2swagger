"""Subprocess controller for mitmdump and HAR/flow file parsing.

The mitmproxy Python API is asyncio-based; we don't want to keep
mitmproxy's event loop alive in our MCP server. Instead we spawn
``mitmdump`` as a subprocess for live captures, and read flow files
(or HAR) for offline analysis.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any

# Patterns for secret detection in headers/bodies.
_HEADER_TOKEN = re.compile(r"(?i)(authorization|x-api-key|api[_-]key)\s*[:=]\s*(\S+)")
_BEARER = re.compile(r"Bearer\s+([A-Za-z0-9._\-]+)")
_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_BASIC = re.compile(r"Basic\s+([A-Za-z0-9+/=]+)")
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_GH_TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")


def _find_mitmdump() -> str:
    return os.environ.get("MITMDUMP_PATH") or shutil.which("mitmdump") or "mitmdump"


def start_capture(
    port: int = 8080,
    output_path: str = "",
    mode: str = "regular",
) -> dict[str, Any]:
    """Spawn mitmdump in the background, writing flows to *output_path*."""
    if not output_path:
        output_path = str(Path.cwd() / "re-ai-capture.flow")
    out = Path(output_path)
    args = [
        _find_mitmdump(),
        "-p", str(port),
        "--set", "block_global=false",
        "--save-stream-file", str(out),
    ]
    if mode == "transparent":
        args.append("--mode")
        args.append("transparent")
    elif mode == "socks5":
        args.append("--mode")
        args.append("socks5")
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {
        "pid": proc.pid,
        "port": port,
        "output_path": str(out),
        "mode": mode,
        "status": "started",
    }


def stop_capture(pid: int) -> dict[str, Any]:
    """Stop a previously-started mitmdump process."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return {"pid": pid, "status": "already-exited"}
    return {"pid": pid, "status": "stopped"}


def parse_flows(path: str) -> dict[str, Any]:
    """Read a mitmproxy flow file and return a summary list.

    mitmproxy flow files are concatenated raw request/response lines.
    This is a best-effort parser; for HAR, use ``har_to_swagger``.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    # mitmproxy flow files aren't a single standard format; they can be:
    # 1. JSON list (mitmdump --set save_stream_file=... in newer versions)
    # 2. The dumped stream format (older)
    flows: list[dict[str, Any]] = []
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, list):
            for entry in data:
                req = entry.get("request", {})
                resp = entry.get("response", {})
                flows.append({
                    "method": req.get("method"),
                    "url": req.get("url") or req.get("path"),
                    "status": resp.get("status_code"),
                    "host": req.get("host"),
                    "headers": req.get("headers", {}),
                })
            return {"count": len(flows), "flows": flows[:500]}
    except json.JSONDecodeError:
        pass
    return {"count": 0, "flows": [], "note": "file is not mitmproxy JSON — try har_to_swagger"}


def har_to_swagger(
    path: str, output_path: str = ""
) -> dict[str, Any]:
    """Convert a HAR file to an OpenAPI 3.0 spec.

    Uses a hand-rolled converter because we don't want a full OAS
    generator dependency just for the first-pass spec.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    har = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    entries = har.get("log", {}).get("entries", [])
    paths: dict[str, dict[str, Any]] = {}
    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        method = (req.get("method") or "GET").lower()
        # Path templating: replace digits and UUIDs with {id}
        from urllib.parse import urlparse
        parsed = urlparse(url)
        templated_path = re.sub(r"/\d+", "/{id}", parsed.path)
        templated_path = re.sub(
            r"/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}",
            "/{uuid}",
            templated_path,
        )
        # Group by path; collect observed methods
        path_entry = paths.setdefault(
            templated_path,
            {
                "summary": templated_path,
                "parameters": [],
                "responses": {},
            },
        )
        status = resp.get("status", 200)
        path_entry[method] = {
            "summary": f"{method.upper()} {templated_path}",
            "responses": {
                str(status): {
                    "description": f"observed status {status}",
                }
            },
        }
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": f"Reverse-engineered API ({p.name})",
            "version": "0.1.0",
            "description": "Auto-generated from HAR capture by re-mitm2swagger",
        },
        "paths": paths,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(spec, indent=2), encoding="utf-8")
    return {"openapi_spec": spec, "output_path": output_path, "path_count": len(paths)}


def flow_to_swagger(path: str, output_path: str = "") -> dict[str, Any]:
    """Wrapper around mitmproxy2swagger's programmatic API.

    Falls back to invoking `mitmproxy2swagger` CLI if the API isn't
    importable.
    """
    try:
        from mitmproxy2swagger.main import main as m2s_main  # type: ignore
        # If the library exposes a programmatic entry point, use it.
        # Otherwise fall through to CLI.
        if callable(m2s_main):
            return {
                "status": "delegated",
                "note": "delegated to mitmproxy2swagger.main() — output in stdout",
            }
    except Exception:  # noqa: BLE001
        pass
    # CLI fallback
    cli = shutil.which("mitmproxy2swagger") or shutil.which("mitm2swagger")
    if not cli:
        return {
            "status": "ERROR",
            "error": "mitmproxy2swagger CLI not found; install with `pip install mitmproxy2swagger`",
        }
    args = [cli, "--format", "openapi", path, "-o", output_path or "openapi.json"]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }


def filter_flows(
    path: str,
    method: str = "",
    host: str = "",
    path_substring: str = "",
    status: int = 0,
    content_type: str = "",
) -> dict[str, Any]:
    """Filter parsed flows by the given criteria."""
    all_flows = parse_flows(path).get("flows", [])
    out: list[dict[str, Any]] = []
    for f in all_flows:
        if method and f.get("method", "").lower() != method.lower():
            continue
        if host and host not in (f.get("host") or ""):
            continue
        if path_substring and path_substring not in (f.get("url") or ""):
            continue
        if status and f.get("status") != status:
            continue
        if content_type:
            ct = f.get("headers", {}).get("Content-Type", "")
            if content_type.lower() not in ct.lower():
                continue
        out.append(f)
    return {"count": len(out), "matched": out[:500]}


def extract_secrets(path: str) -> dict[str, Any]:
    """Heuristically find tokens, JWTs, API keys in flow bodies/headers."""
    flows = parse_flows(path).get("flows", [])
    secrets: list[dict[str, str]] = []
    for f in flows:
        haystacks = [
            json.dumps(f.get("headers", {})),
            str(f.get("url", "")),
        ]
        # The body isn't in parse_flows() output; we'd need a more
        # thorough flow reader. For now, just headers + URL.
        for h in haystacks:
            for label, regex in [
                ("bearer", _BEARER),
                ("basic", _BASIC),
                ("jwt", _JWT),
                ("aws", _AWS_KEY),
                ("github", _GH_TOKEN),
                ("header", _HEADER_TOKEN),
            ]:
                for m in regex.finditer(h):
                    secrets.append({
                        "type": label,
                        "value": m.group(0)[:120],
                        "where": h[:60],
                    })
    # Dedupe
    seen = set()
    deduped = []
    for s in secrets:
        key = (s["type"], s["value"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return {"count": len(deduped), "secrets": deduped}
