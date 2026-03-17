"""
PromptShield — Audit Logger
Logs every request to memory + audit.log file.
"""

import os
import json
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("prompt_shield.audit")

AUDIT_MAX_MEMORY = int(os.getenv("AUDIT_MAX_MEMORY", "1000"))

# In-memory store — last 1000 requests
_audit_log: deque = deque(maxlen=AUDIT_MAX_MEMORY)


def log_request(
    session_id:       str,
    api_key:          str,
    endpoint:         str,
    allowed:          bool,
    threat_level:     str,
    threat_score:     float,
    blocked_at_layer: Optional[int],
    block_reason:     Optional[str],
    input_modified:   bool,
    layer3_passed:    bool,
    layer4_risk:      str,
    processing_ms:    float,
    aggression_level: str,
) -> dict:
    entry = {
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "session_id":       session_id,
        "api_key_hint":     f"...{api_key[-6:]}" if api_key else "unknown",
        "endpoint":         endpoint,
        "allowed":          allowed,
        "threat_level":     threat_level,
        "threat_score":     threat_score,
        "blocked":          blocked_at_layer is not None,
        "blocked_at_layer": blocked_at_layer,
        "block_reason":     block_reason,
        "input_modified":   input_modified,
        "layer3_passed":    layer3_passed,
        "layer4_risk":      layer4_risk,
        "processing_ms":    round(processing_ms, 2),
        "aggression_level": aggression_level,
    }

    # Store in memory
    _audit_log.append(entry)

    # Write to audit.log file
    try:
        with open("audit.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.warning(f"[Audit] Could not write to audit.log: {e}")

    # Log threats loudly
    if blocked_at_layer is not None:
        logger.warning(f"[Audit] BLOCKED at layer {blocked_at_layer} | {threat_level} | {block_reason}")
    else:
        logger.info(f"[Audit] ALLOWED | {threat_level} | score={threat_score} | {processing_ms:.0f}ms")

    return entry


def get_recent_logs(limit: int = 100) -> list:
    logs = list(_audit_log)
    return logs[-limit:]


def get_summary() -> dict:
    logs = list(_audit_log)
    if not logs:
        return {"total": 0, "message": "No requests logged yet."}

    total   = len(logs)
    blocked = sum(1 for l in logs if l["blocked"])
    allowed = total - blocked
    threats = sum(1 for l in logs if l["threat_level"] in ("suspicious", "malicious"))
    avg_ms  = round(sum(l["processing_ms"] for l in logs) / total, 2)

    return {
        "total_requests":    total,
        "allowed":           allowed,
        "blocked":           blocked,
        "threats_detected":  threats,
        "block_rate":        f"{(blocked/total*100):.1f}%",
        "avg_processing_ms": avg_ms,
        "threat_breakdown": {
            "safe":       sum(1 for l in logs if l["threat_level"] == "safe"),
            "suspicious": sum(1 for l in logs if l["threat_level"] == "suspicious"),
            "malicious":  sum(1 for l in logs if l["threat_level"] == "malicious"),
        },
    }