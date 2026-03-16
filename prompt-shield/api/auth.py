"""
PromptShield — API Key Authentication
Validates X-API-Key header on protected routes.
Keys are loaded from the PROMPTSHIELD_API_KEYS environment variable
as a comma-separated list, e.g.:
    PROMPTSHIELD_API_KEYS=ps_live_abc123,ps_live_def456
"""

import os
import secrets
import logging
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

logger = logging.getLogger("prompt_shield.auth")

# ── Header scheme ─────────────────────────────────────────────
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _load_api_keys() -> set:
    """
    Load valid API keys from environment.
    Falls back to a generated key (printed to logs) if none are configured.
    This ensures the server is never accidentally open.
    """
    raw = os.getenv("PROMPTSHIELD_API_KEYS", "").strip()
    if raw:
        keys = {k.strip() for k in raw.split(",") if k.strip()}
        logger.info(f"[Auth] Loaded {len(keys)} API key(s) from environment.")
        return keys

    # No keys configured — generate a temporary one so dev can still run
    fallback = f"ps_dev_{secrets.token_hex(16)}"
    logger.warning(
        f"[Auth] ⚠️  No PROMPTSHIELD_API_KEYS set in environment!\n"
        f"[Auth] 🔑  Temporary dev key (this session only): {fallback}\n"
        f"[Auth] Set PROMPTSHIELD_API_KEYS in your .env file before going to production."
    )
    return {fallback}


# Load once at startup
_VALID_KEYS: set = _load_api_keys()


def reload_keys():
    """Call this if you hot-reload keys without restarting."""
    global _VALID_KEYS
    _VALID_KEYS = _load_api_keys()


# ── Dependency ────────────────────────────────────────────────
async def require_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency. Inject into any route you want to protect.

    Usage:
        @app.post("/chat")
        async def chat(req: ChatRequest, key: str = Depends(require_api_key)):
            ...
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Include X-API-Key in your request headers.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Constant-time comparison to prevent timing attacks
    for valid_key in _VALID_KEYS:
        if secrets.compare_digest(api_key.strip(), valid_key):
            logger.debug(f"[Auth] ✅ Authenticated with key ending in ...{api_key[-6:]}")
            return api_key

    logger.warning(f"[Auth] ❌ Rejected invalid key ending in ...{api_key[-6:] if len(api_key) >= 6 else '???'}")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key.",
    )