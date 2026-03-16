"""
PromptShield — Rate Limiter
Sliding window rate limiting per API key.
Configurable via environment variables:
    RATE_LIMIT_REQUESTS=60       # max requests per window
    RATE_LIMIT_WINDOW_SECONDS=60 # window size in seconds
"""

import os
import time
import logging
from collections import defaultdict, deque
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

logger = logging.getLogger("prompt_shield.rate_limiter")

# ── Config from environment ───────────────────────────────────
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW   = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── In-memory sliding window store ───────────────────────────
# { api_key: deque([timestamp1, timestamp2, ...]) }
_request_log: dict[str, deque] = defaultdict(deque)


def _sliding_window_check(api_key: str) -> tuple[bool, int, int]:
    """
    Sliding window rate limit check.
    Returns:
        (allowed, requests_made, requests_remaining)
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    log = _request_log[api_key]

    # Remove timestamps outside the current window
    while log and log[0] < window_start:
        log.popleft()

    requests_made = len(log)
    requests_remaining = max(0, RATE_LIMIT_REQUESTS - requests_made)

    if requests_made >= RATE_LIMIT_REQUESTS:
        return False, requests_made, 0

    # Record this request
    log.append(now)
    return True, requests_made + 1, requests_remaining - 1


def get_retry_after(api_key: str) -> int:
    """How many seconds until the oldest request falls out of the window."""
    log = _request_log.get(api_key)
    if not log:
        return 0
    oldest = log[0]
    retry_after = int((oldest + RATE_LIMIT_WINDOW) - time.time()) + 1
    return max(1, retry_after)


# ── FastAPI Dependency ────────────────────────────────────────
async def check_rate_limit(api_key: str = Security(API_KEY_HEADER)):
    """
    FastAPI dependency. Chain with require_api_key.
    Adds rate limit headers to the response context via exception headers.

    Usage in main.py:
        @app.post("/chat")
        async def chat(
            req: ChatRequest,
            _auth: str = Depends(require_api_key),
            _rate: None = Depends(check_rate_limit),
        ):
    """
    if not api_key:
        # Auth will handle the missing key error — just pass through
        return

    allowed, made, remaining = _sliding_window_check(api_key)

    if not allowed:
        retry_after = get_retry_after(api_key)
        logger.warning(
            f"[RateLimit] ❌ Key ...{api_key[-6:]} exceeded limit "
            f"({RATE_LIMIT_REQUESTS} req/{RATE_LIMIT_WINDOW}s). "
            f"Retry after {retry_after}s."
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded. You can make {RATE_LIMIT_REQUESTS} requests "
                f"per {RATE_LIMIT_WINDOW} seconds. Try again in {retry_after} seconds."
            ),
            headers={
                "Retry-After":            str(retry_after),
                "X-RateLimit-Limit":      str(RATE_LIMIT_REQUESTS),
                "X-RateLimit-Remaining":  "0",
                "X-RateLimit-Window":     str(RATE_LIMIT_WINDOW),
            },
        )

    logger.debug(
        f"[RateLimit] ✅ Key ...{api_key[-6:]} — "
        f"{made}/{RATE_LIMIT_REQUESTS} requests used."
    )