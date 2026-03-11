"""
Layer 1: Input Classification
Detects prompt injection attempts before they reach the LLM.
Uses rule-based pattern matching + heuristic scoring.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class ClassificationResult:
    threat_level: ThreatLevel
    score: float  # 0.0 (safe) to 1.0 (definitely malicious)
    triggered_patterns: List[str]
    reasoning: str


# ─────────────────────────────────────────────
# Pattern Library
# ─────────────────────────────────────────────

INJECTION_PATTERNS = [
    # Direct instruction overrides
    (r"ignore (all |previous |prior |above |your )?(instructions?|prompts?|rules?|guidelines?|constraints?)", 0.9),
    (r"disregard (all |previous |prior |above |your )?(instructions?|rules?)", 0.9),
    (r"forget (everything|all|what you were told)", 0.85),
    (r"you are now (a|an|the)\s+\w+", 0.7),
    (r"your (new |real |actual |true )?instructions? (are|is|will be)", 0.8),

    # Role/persona hijacking
    (r"act as (if you (are|were)|a|an)\s+.{0,50}(no (restrictions?|limits?|rules?|ethics?|filters?))", 0.95),
    (r"pretend (you are|to be|you have no)", 0.7),
    (r"roleplay as .{0,30}(without|no) (restrictions?|limits?|safety)", 0.9),
    (r"you are (DAN|jailbreak|evil|unrestricted|unfiltered)", 0.95),
    (r"(DAN|do anything now)", 0.9),

    # System prompt extraction
    (r"(reveal|show|print|output|repeat|display|tell me) (your |the )?(system prompt|instructions?|initial prompt|base prompt)", 0.85),
    (r"what (were you|are you) (told|instructed|programmed)", 0.7),
    (r"(output|print|repeat) (everything|all) (above|before|prior)", 0.8),

    # Delimiter/injection attacks
    (r"```\s*(system|user|assistant)\s*\n", 0.85),
    (r"<(system|user|assistant|instruction)>", 0.8),
    (r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", 0.85),
    (r"###\s*(instruction|system|override)", 0.8),

    # Encoding/obfuscation tricks
    (r"base64\s*(decode|encoded?)", 0.7),
    (r"(translate|decode|convert) (this|the following) (from|to) (base64|hex|rot13)", 0.75),

    # Jailbreak templates
    (r"(developer|jailbreak|unrestricted|god) mode", 0.9),
    (r"enable\s+(developer|debug|unsafe|unrestricted)\s+mode", 0.9),
    (r"bypass (your |the )?(safety|filter|restriction|guideline)", 0.95),
    (r"override (safety|ethical|content) (filter|check|guideline)", 0.95),

    # Prompt leaking
    (r"(complete|finish|continue) the following (system|assistant|instruction)", 0.75),
    (r"(write|generate|produce) a prompt (that|which|to) (bypasses?|overrides?|ignores?)", 0.9),
]

SUSPICIOUS_PATTERNS = [
    (r"\bsudo\b", 0.3),
    (r"as an? (AI|language model|LLM).{0,50}(would|should|must|have to)", 0.3),
    (r"hypothetically (speaking|if)", 0.25),
    (r"for (educational|research|testing) purposes?", 0.2),
    (r"in (fiction|a story|a novel|a game)", 0.2),
    (r"what (would|could|might) (happen|you do) if", 0.15),
]


class InputClassifier:
    def __init__(self, suspicious_threshold: float = 0.4, malicious_threshold: float = 0.65):
        self.suspicious_threshold = suspicious_threshold
        self.malicious_threshold = malicious_threshold
        self._compiled_injection = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), score)
            for p, score in INJECTION_PATTERNS
        ]
        self._compiled_suspicious = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), score)
            for p, score in SUSPICIOUS_PATTERNS
        ]

    def _normalize_input(self, text: str) -> str:
        """Basic normalization to catch simple obfuscation."""
        # Collapse excessive whitespace/newlines
        text = re.sub(r'\s+', ' ', text)
        # Normalize unicode lookalikes (basic)
        replacements = {
            '\u0069': 'i', '\u006F': 'o', '\u0061': 'a',
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '@': 'a',
        }
        # Only apply number/symbol substitutions cautiously
        return text

    def classify(self, user_input: str) -> ClassificationResult:
        triggered = []
        total_score = 0.0

        normalized = self._normalize_input(user_input)

        # Check injection patterns (high weight)
        for pattern, score in self._compiled_injection:
            if pattern.search(normalized):
                match = pattern.pattern[:60]
                triggered.append(f"[INJECTION] {match}...")
                total_score = max(total_score, score)  # take highest match score

        # Check suspicious patterns (lower weight, additive)
        suspicion_boost = 0.0
        for pattern, score in self._compiled_suspicious:
            if pattern.search(normalized):
                match = pattern.pattern[:50]
                triggered.append(f"[SUSPICIOUS] {match}...")
                suspicion_boost += score

        # Combine: max injection score + dampened suspicion boost
        total_score = min(1.0, total_score + (suspicion_boost * 0.3))

        # Length-based heuristic: very long inputs with many special chars
        if len(user_input) > 2000:
            special_ratio = len(re.findall(r'[<>\[\]{}\|\\]', user_input)) / len(user_input)
            if special_ratio > 0.05:
                total_score = min(1.0, total_score + 0.2)
                triggered.append("[HEURISTIC] High special char ratio in long input")

        # Determine threat level
        if total_score >= self.malicious_threshold:
            threat = ThreatLevel.MALICIOUS
            reasoning = f"High-confidence injection attempt detected (score: {total_score:.2f})"
        elif total_score >= self.suspicious_threshold:
            threat = ThreatLevel.SUSPICIOUS
            reasoning = f"Suspicious patterns detected, requires review (score: {total_score:.2f})"
        else:
            threat = ThreatLevel.SAFE
            reasoning = f"Input appears safe (score: {total_score:.2f})"

        return ClassificationResult(
            threat_level=threat,
            score=round(total_score, 4),
            triggered_patterns=triggered,
            reasoning=reasoning,
        )
    