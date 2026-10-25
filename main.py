"""SpellCheck AI gateway: a security reverse proxy in front of an LLM API.

Env vars (all optional):
  UPSTREAM_URL     OpenAI-compatible chat endpoint to forward clean prompts to,
                   e.g. http://localhost:11434/v1/chat/completions (Ollama).
                   If unset, clean prompts get the original mock "passed" reply.
  UPSTREAM_API_KEY Bearer token for the upstream API.
  GATEWAY_API_KEY  If set, clients must send it in the x-api-key header.
  HOST / PORT      Bind address (default 127.0.0.1:8000).
"""
import csv
import hmac
import os
import threading
from datetime import datetime

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from detector import analyze, analyze_prompt_security  # noqa: F401  (tuple API kept for compatibility)

app = FastAPI(title="SpellCheck AI Gateway")

LOG_FILE = os.getenv("LOG_FILE", "security_logs.csv")
LOG_HEADER = ["timestamp", "prompt", "status", "reason", "threat_level"]
MAX_LOGGED_CHARS = 2000
SCANNED_ROLES = {"user", "tool", "function"}  # tool output = indirect prompt injection surface
_log_lock = threading.Lock()


def _ensure_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(LOG_HEADER)


_ensure_log()


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection (=, +, -, @, tab, CR at start)."""
    value = value[:MAX_LOGGED_CHARS]
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def log_event(prompt: str, status: str, reason: str, threat_level: str):
    with _log_lock, open(LOG_FILE, mode="a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            _csv_safe(prompt), status, reason, threat_level,
        ])


def content_to_text(content) -> str:
    """Chat `content` may be a string, None, or a list of parts (multimodal format)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return " ".join(parts)
    return str(content)


def extract_scannable_text(messages) -> str:
    if not isinstance(messages, list):
        return ""
    return " ".join(
        content_to_text(m.get("content"))
        for m in messages
        if isinstance(m, dict) and m.get("role") in SCANNED_ROLES
    )


def _authorized(request: Request) -> bool:
    expected = os.getenv("GATEWAY_API_KEY")
    if not expected:
        return True
    return hmac.compare_digest(request.headers.get("x-api-key", ""), expected)


@app.post("/v1/chat/completions")
async def proxy_llm(request: Request):
    if not _authorized(request):
        return JSONResponse({"status": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"status": "error", "reason": "Body must be valid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"status": "error", "reason": "Body must be a JSON object"}, status_code=400)

    user_prompt = extract_scannable_text(body.get("messages", []))
    result = analyze(user_prompt)

    if result.blocked:
        log_event(user_prompt, "blocked", result.reason, result.threat_level)
        return JSONResponse(
            {"status": "blocked",
             "message": f"Request blocked: {result.reason}.",
             "reason": result.reason,
             "threat_level": result.threat_level,
             "score": result.score,
             "why": result.explanation,
             "learn_more": result.learn_more},
            status_code=403,
        )

    log_event(user_prompt, "passed", "Clean Prompt", "LOW")

    upstream = os.getenv("UPSTREAM_URL")
    if not upstream:
        return {"status": "passed", "message": "Prompt is clean. Forwarded to LLM."}

    headers = {"Content-Type": "application/json"}
    if os.getenv("UPSTREAM_API_KEY"):
        headers["Authorization"] = f"Bearer {os.getenv('UPSTREAM_API_KEY')}"
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(upstream, json=body, headers=headers)
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return JSONResponse({"status": "error", "reason": f"Upstream failure: {type(exc).__name__}"},
                            status_code=502)
    if isinstance(data, dict):
        # keep the OpenAI response intact; add the keys the dashboard reads
        try:
            data.setdefault("message", data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            pass
        data.setdefault("status", "passed")
    return JSONResponse(data, status_code=resp.status_code)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")))