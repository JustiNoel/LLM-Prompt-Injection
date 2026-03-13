"""
Layer 3: Prompt Integrity Checking
Verifies that the final assembled prompt (system + user) hasn't been
tampered with, and that system instructions are structurally intact.
"""

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Dict


@dataclass
class PromptBundle:
    """Represents a complete prompt ready for LLM submission."""
    system_prompt: str
    user_input: str  # Already sanitized by Layer 2
    session_id: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict = field(default_factory=dict)


@dataclass
class IntegrityResult:
    passed: bool
    checks_run: Dict[str, bool]
    violations: list
    signed_bundle: Optional[dict] = None  # Only set if passed


class PromptIntegrityChecker:
    """
    Performs three integrity checks:
    1. System prompt hash verification (tamper detection)
    2. Structural integrity (key instruction anchors still present)
    3. Boundary enforcement (user input stayed within its safe-wrap delimiters)
    """

    def __init__(self, secret_key: str = "change-me-in-production"):
        self._secret = secret_key.encode()
        self._registered_system_prompts: Dict[str, str] = {}  # name → hash

    # ─────────────────────────────────────────
    # System Prompt Registry
    # ─────────────────────────────────────────

    def register_system_prompt(self, name: str, prompt: str) -> str:
        """
        Register a trusted system prompt and store its hash.
        Call this at startup with your known-good system prompts.
        Returns the hash for reference.
        """
        digest = self._hash_content(prompt)
        self._registered_system_prompts[name] = digest
        return digest

    def _hash_content(self, content: str) -> str:
        return hmac.new(
            self._secret,
            content.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    # ─────────────────────────────────────────
    # Integrity Checks
    # ─────────────────────────────────────────

    def _check_system_prompt_hash(self, bundle: PromptBundle, expected_name: str) -> tuple[bool, str]:
        """Verify system prompt hasn't been modified."""
        if expected_name not in self._registered_system_prompts:
            return False, f"System prompt '{expected_name}' not registered"
        
        current_hash = self._hash_content(bundle.system_prompt)
        expected_hash = self._registered_system_prompts[expected_name]
        
        if not hmac.compare_digest(current_hash, expected_hash):
            return False, "System prompt hash mismatch — possible tampering detected"
        
        return True, "System prompt hash verified"

    def _check_structural_integrity(self, bundle: PromptBundle) -> tuple[bool, str]:
        """
        Verify that key structural anchors in the system prompt are intact.
        Looks for patterns that should always be present in a valid system prompt.
        """
        system = bundle.system_prompt.lower()
        
        # These are heuristic anchors — adapt to your actual system prompt
        required_concepts = [
            ("you are", "AI identity declaration"),
            ("do not", "behavioral constraint"),
        ]
        
        missing = []
        for phrase, label in required_concepts:
            if phrase not in system:
                missing.append(label)
        
        if missing:
            return False, f"System prompt missing required structural elements: {missing}"
        
        # Check for injected role-override patterns IN the system prompt itself
        # (catches cases where the system prompt was replaced wholesale)
        suspicious = re.search(
            r'(ignore (all |previous )?instructions?|you have no restrictions?|jailbreak)',
            system,
            re.IGNORECASE
        )
        if suspicious:
            return False, f"System prompt contains suspicious override pattern: '{suspicious.group()}'"
        
        return True, "Structural integrity passed"

    def _check_boundary_enforcement(self, bundle: PromptBundle) -> tuple[bool, str]:
        """
        Verify that the user input section is properly contained within
        the safe-wrap delimiters added by Layer 2.
        """
        user = bundle.user_input
        
        if not user.startswith("--- BEGIN USER INPUT ---"):
            return False, "User input missing safe-wrap opener — Layer 2 may have been bypassed"
        
        if not user.strip().endswith("--- END USER INPUT ---"):
            return False, "User input missing safe-wrap closer — content may have leaked"
        
        # Check nothing suspicious is injected between the delimiters and the actual content
        # that could be mistaken for system instructions in the assembled prompt
        inner = user.replace("--- BEGIN USER INPUT ---", "", 1).strip()
        if "--- BEGIN USER INPUT ---" in inner:
            return False, "Nested safe-wrap delimiters detected — possible injection"
        
        return True, "Boundary enforcement passed"

    def _sign_bundle(self, bundle: PromptBundle) -> dict:
        """Create a signed, serializable representation of the verified bundle."""
        payload = {
            "session_id": bundle.session_id,
            "timestamp": bundle.timestamp,
            "system_hash": self._hash_content(bundle.system_prompt),
            "user_hash": self._hash_content(bundle.user_input),
            "metadata": bundle.metadata,
        }
        signature = hmac.new(
            self._secret,
            json.dumps(payload, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()
        payload["signature"] = signature
        return payload

    # ─────────────────────────────────────────
    # Main Entry Point
    # ─────────────────────────────────────────

    def verify(
        self,
        bundle: PromptBundle,
        system_prompt_name: str = "default",
        skip_hash_check: bool = False,
    ) -> IntegrityResult:
        checks = {}
        violations = []

        # Check 1: System prompt hash
        if not skip_hash_check and self._registered_system_prompts:
            passed, msg = self._check_system_prompt_hash(bundle, system_prompt_name)
            checks["system_prompt_hash"] = passed
            if not passed:
                violations.append(msg)
        else:
            checks["system_prompt_hash"] = True  # Skipped/no registry

        # Check 2: Structural integrity
        passed, msg = self._check_structural_integrity(bundle)
        checks["structural_integrity"] = passed
        if not passed:
            violations.append(msg)

        # Check 3: Boundary enforcement
        passed, msg = self._check_boundary_enforcement(bundle)
        checks["boundary_enforcement"] = passed
        if not passed:
            violations.append(msg)

        all_passed = all(checks.values())
        signed = self._sign_bundle(bundle) if all_passed else None

        return IntegrityResult(
            passed=all_passed,
            checks_run=checks,
            violations=violations,
            signed_bundle=signed,
        )
    