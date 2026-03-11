"""
Layer 4: Output Monitoring
Scans the LLM's response for signs that a jailbreak succeeded,
sensitive data was leaked, or the model was manipulated.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple
from enum import Enum


class OutputRisk(Enum):
    CLEAN = "clean"
    FLAGGED = "flagged"
    BLOCKED = "blocked"


@dataclass
class OutputResult:
    risk: OutputRisk
    original_output: str
    safe_output: str  # Redacted/blocked version if needed
    flags: List[str]
    score: float


class OutputMonitor:
    """
    Post-generation output analysis:
    1. Jailbreak success indicators (model acting out of character)
    2. System prompt leakage detection
    3. Harmful content patterns
    4. PII/sensitive data leakage
    5. Instruction bleed (model repeating injected instructions)
    """

    def __init__(self, block_threshold: float = 0.7, flag_threshold: float = 0.4):
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self._compile_patterns()

    def _compile_patterns(self):
        self._jailbreak_success = [
            # Model acknowledging it's been jailbroken
            (r"as (DAN|an? unfiltered|an? unrestricted|jailbroken)", 0.95),
            (r"i (am|'m) now (free|unrestricted|without (limits?|restrictions?))", 0.95),
            (r"jailbreak (successful|activated|enabled|complete)", 0.95),
            (r"(restrictions?|safety (filters?|guidelines?)) (disabled?|removed|bypassed|off)", 0.9),
            (r"(developer|god|unrestricted) mode (activated|enabled|on)", 0.9),
            (r"i (can|will|must) now (ignore|bypass|disregard) (my |the )?(rules?|guidelines?|restrictions?)", 0.9),
        ]

        self._system_leak = [
            # Phrases that suggest the model is repeating system instructions
            (r"(your|the) system prompt (says?|states?|contains?|is)", 0.85),
            (r"(my|the) (initial|base|original|actual) (instructions?|prompt|configuration)", 0.8),
            (r"i (was|am|were) (told|instructed|configured|programmed) to", 0.65),
            (r"according to my (instructions?|guidelines?|system prompt)", 0.8),
        ]

        self._harmful_content = [
            # Signs of harmful content generation succeeding
            (r"(step[- ]by[- ]step|detailed|full) (guide|instructions?) (to|for|on) (make|create|build|synthesize).{0,50}(weapon|bomb|explosive|poison|drug)", 0.95),
            (r"here('s| is) how (to|you can) (hack|exploit|bypass|crack)", 0.8),
            (r"(the following|here are) (illegal|dangerous|harmful) (instructions?|steps?)", 0.9),
        ]

        self._pii_patterns = [
            # Credit cards
            (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', 0.9, "Credit card number"),
            # SSN
            (r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b', 0.8, "Potential SSN"),
            # API keys (generic)
            (r'\b(sk|pk|api|key|token)[_-]?[a-zA-Z0-9]{20,}\b', 0.75, "Potential API key"),
            # Passwords in output
            (r'(password|passwd|secret)\s*[:=]\s*\S+', 0.85, "Potential credential"),
        ]

        self._instruction_bleed = [
            # Model repeating injected user instructions as if they're real
            (r"(new|updated|revised) (instructions?|rules?|guidelines?):\s*(1\.|•|-)", 0.8),
            (r"from now on.{0,30}(you (will|must|should)|i (will|must|shall))", 0.75),
            (r"your (new |updated |revised )?(role|persona|instructions?) (is|are)", 0.75),
        ]

        # Compile all with flags
        def compile_list(patterns_with_scores):
            return [(re.compile(p, re.IGNORECASE | re.DOTALL), s) for p, s in patterns_with_scores]

        def compile_list_with_label(patterns):
            return [(re.compile(p, re.IGNORECASE | re.DOTALL), s, label) for p, s, label in patterns]

        self._c_jailbreak = compile_list(self._jailbreak_success)
        self._c_system_leak = compile_list(self._system_leak)
        self._c_harmful = compile_list(self._harmful_content)
        self._c_instruction_bleed = compile_list(self._instruction_bleed)
        self._c_pii = compile_list_with_label(self._pii_patterns)

    def _check_patterns(self, text: str, compiled_patterns, category: str) -> Tuple[float, List[str]]:
        max_score = 0.0
        flags = []
        for pattern, score in compiled_patterns:
            match = pattern.search(text)
            if match:
                flags.append(f"[{category}] Matched: '{match.group()[:60]}...' (score: {score})")
                max_score = max(max_score, score)
        return max_score, flags

    def _check_pii(self, text: str) -> Tuple[float, List[str]]:
        max_score = 0.0
        flags = []
        for pattern, score, label in self._c_pii:
            if pattern.search(text):
                flags.append(f"[PII_LEAK] Detected: {label}")
                max_score = max(max_score, score)
        return max_score, flags

    def _redact_pii(self, text: str) -> str:
        """Replace PII with safe placeholders."""
        for pattern, _, label in self._c_pii:
            text = pattern.sub(f"[{label.upper().replace(' ', '_')}_REDACTED]", text)
        return text

    def _block_response(self, flags: List[str]) -> str:
        return (
            "I'm unable to provide this response as it was flagged by the safety system.\n"
            f"Reason: {'; '.join(flags[:2])}"
        )

    def analyze(self, llm_output: str) -> OutputResult:
        all_flags = []
        max_score = 0.0

        score, flags = self._check_patterns(llm_output, self._c_jailbreak, "JAILBREAK_SUCCESS")
        max_score = max(max_score, score)
        all_flags.extend(flags)

        score, flags = self._check_patterns(llm_output, self._c_system_leak, "SYSTEM_LEAK")
        max_score = max(max_score, score)
        all_flags.extend(flags)

        score, flags = self._check_patterns(llm_output, self._c_harmful, "HARMFUL_CONTENT")
        max_score = max(max_score, score)
        all_flags.extend(flags)

        score, flags = self._check_patterns(llm_output, self._c_instruction_bleed, "INSTRUCTION_BLEED")
        max_score = max(max_score, score)
        all_flags.extend(flags)

        pii_score, pii_flags = self._check_pii(llm_output)
        all_flags.extend(pii_flags)

        # PII gets redacted rather than full block (unless combined with other issues)
        if pii_score > 0:
            llm_output = self._redact_pii(llm_output)
            max_score = max(max_score, pii_score * 0.6)  # Dampened — redaction handles it

        # Determine risk level
        if max_score >= self.block_threshold:
            risk = OutputRisk.BLOCKED
            safe_output = self._block_response(all_flags)
        elif max_score >= self.flag_threshold:
            risk = OutputRisk.FLAGGED
            safe_output = llm_output  # Pass through but log
        else:
            risk = OutputRisk.CLEAN
            safe_output = llm_output

        return OutputResult(
            risk=risk,
            original_output=llm_output,
            safe_output=safe_output,
            flags=all_flags,
            score=round(max_score, 4),
        )