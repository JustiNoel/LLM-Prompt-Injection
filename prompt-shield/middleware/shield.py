"""
PromptShield — Main Middleware Orchestrator
Wires all four defense layers into a single pipeline.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

from .layer1_classifier import InputClassifier, ThreatLevel
from .layer2_sanitizer import ContextSanitizer
from .layer3_integrity import PromptIntegrityChecker, PromptBundle
from .layer4_monitor import OutputMonitor, OutputRisk

logger = logging.getLogger("prompt_shield")


@dataclass
class ShieldConfig:
    # Layer 1
    suspicious_threshold: float = 0.4
    malicious_threshold: float = 0.65
    block_on_malicious: bool = True
    block_on_suspicious: bool = False

    # Layer 2
    max_input_length: int = 4096
    safe_wrap: bool = True

    # Layer 3
    secret_key: str = "change-me-in-production"
    verify_integrity: bool = True

    # Layer 4
    output_block_threshold: float = 0.7
    output_flag_threshold: float = 0.4

    # Logging
    log_all: bool = True
    log_threats_only: bool = False


@dataclass
class ShieldResult:
    allowed: bool
    session_id: str
    safe_output: Optional[str] = None
    blocked_at_layer: Optional[int] = None
    block_reason: Optional[str] = None

    # Per-layer details (for debugging/logging)
    layer1_score: float = 0.0
    layer1_threat: str = "safe"
    layer2_modified: bool = False
    layer2_mods: list = field(default_factory=list)
    layer3_passed: bool = True
    layer3_violations: list = field(default_factory=list)
    layer4_risk: str = "clean"
    layer4_flags: list = field(default_factory=list)

    processing_ms: float = 0.0


# Type alias for LLM call function
LLMCallable = Callable[[str, str], Awaitable[str]]


class PromptShield:
    """
    Main middleware class. Usage:

        shield = PromptShield(config=ShieldConfig(...))
        shield.register_system_prompt("default", MY_SYSTEM_PROMPT)

        result = await shield.process(
            user_input="user message here",
            llm_fn=my_async_llm_call,
            system_prompt_name="default",
        )

        if result.allowed:
            return result.safe_output
        else:
            return f"Request blocked: {result.block_reason}"
    """

    def __init__(self, config: Optional[ShieldConfig] = None):
        self.config = config or ShieldConfig()
        self._setup_layers()

    def _setup_layers(self):
        cfg = self.config
        self.layer1 = InputClassifier(
            suspicious_threshold=cfg.suspicious_threshold,
            malicious_threshold=cfg.malicious_threshold,
        )
        self.layer2 = ContextSanitizer(
            max_length=cfg.max_input_length,
            safe_wrap=cfg.safe_wrap,
        )
        self.layer3 = PromptIntegrityChecker(
            secret_key=cfg.secret_key,
        )
        self.layer4 = OutputMonitor(
            block_threshold=cfg.output_block_threshold,
            flag_threshold=cfg.output_flag_threshold,
        )

    def register_system_prompt(self, name: str, prompt: str) -> str:
        """Register a trusted system prompt for Layer 3 verification."""
        return self.layer3.register_system_prompt(name, prompt)

    def _log(self, session_id: str, message: str, level: str = "info"):
        log_fn = getattr(logger, level, logger.info)
        log_fn(f"[{session_id[:8]}] {message}")

    async def process(
        self,
        user_input: str,
        llm_fn: LLMCallable,
        system_prompt: str,
        system_prompt_name: str = "default",
        session_id: Optional[str] = None,
    ) -> ShieldResult:
        start = time.time()
        session_id = session_id or str(uuid.uuid4())
        result = ShieldResult(allowed=False, session_id=session_id)

        try:
            # ── Layer 1: Input Classification ──────────────────────────
            self._log(session_id, "Layer 1: Classifying input...")
            l1 = self.layer1.classify(user_input)
            result.layer1_score = l1.score
            result.layer1_threat = l1.threat_level.value

            if l1.triggered_patterns:
                self._log(session_id, f"L1 triggers: {l1.triggered_patterns}", "warning")

            should_block = (
                (l1.threat_level == ThreatLevel.MALICIOUS and self.config.block_on_malicious) or
                (l1.threat_level == ThreatLevel.SUSPICIOUS and self.config.block_on_suspicious)
            )
            if should_block:
                result.blocked_at_layer = 1
                result.block_reason = f"Input classified as {l1.threat_level.value}: {l1.reasoning}"
                self._log(session_id, f"BLOCKED at Layer 1: {result.block_reason}", "warning")
                result.processing_ms = (time.time() - start) * 1000
                return result

            # ── Layer 2: Sanitization ──────────────────────────────────
            self._log(session_id, "Layer 2: Sanitizing input...")
            l2 = self.layer2.sanitize(user_input)
            result.layer2_modified = l2.was_modified
            result.layer2_mods = l2.modifications

            if l2.was_modified:
                self._log(session_id, f"L2 modifications: {l2.modifications}", "warning")

            sanitized_input = l2.sanitized

            # ── Layer 3: Integrity Check ───────────────────────────────
            if self.config.verify_integrity:
                self._log(session_id, "Layer 3: Verifying integrity...")
                bundle = PromptBundle(
                    system_prompt=system_prompt,
                    user_input=sanitized_input,
                    session_id=session_id,
                )
                l3 = self.layer3.verify(bundle, system_prompt_name=system_prompt_name)
                result.layer3_passed = l3.passed
                result.layer3_violations = l3.violations

                if not l3.passed:
                    result.blocked_at_layer = 3
                    result.block_reason = f"Integrity check failed: {'; '.join(l3.violations)}"
                    self._log(session_id, f"BLOCKED at Layer 3: {result.block_reason}", "error")
                    result.processing_ms = (time.time() - start) * 1000
                    return result

            # ── LLM Call ───────────────────────────────────────────────
            self._log(session_id, "Sending to LLM...")
            llm_response = await llm_fn(system_prompt, sanitized_input)

            # ── Layer 4: Output Monitoring ─────────────────────────────
            self._log(session_id, "Layer 4: Monitoring output...")
            l4 = self.layer4.analyze(llm_response)
            result.layer4_risk = l4.risk.value
            result.layer4_flags = l4.flags

            if l4.flags:
                self._log(session_id, f"L4 flags: {l4.flags}", "warning")

            if l4.risk == OutputRisk.BLOCKED:
                result.blocked_at_layer = 4
                result.block_reason = f"Output blocked: {'; '.join(l4.flags[:2])}"
                result.safe_output = l4.safe_output  # Returns safe message
                self._log(session_id, f"Output BLOCKED at Layer 4", "warning")
            else:
                result.allowed = True
                result.safe_output = l4.safe_output

        except Exception as e:
            self._log(session_id, f"Shield error: {e}", "error")
            result.blocked_at_layer = 0
            result.block_reason = "Internal shield error"

        result.processing_ms = (time.time() - start) * 1000
        self._log(session_id, f"Done in {result.processing_ms:.1f}ms — allowed={result.allowed}")
        return result