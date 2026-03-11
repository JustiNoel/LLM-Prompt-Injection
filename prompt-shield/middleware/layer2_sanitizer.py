"""
Layer 2: Context Sanitization
Strips, neutralizes, or escapes dangerous patterns in user input
before it's injected into the prompt template.
"""

import re
import html
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class SanitizationResult:
    original: str
    sanitized: str
    modifications: List[str]
    was_modified: bool


class ContextSanitizer:
    """
    Sanitizes user input by:
    1. Escaping prompt delimiter injections
    2. Neutralizing role-override attempts
    3. Stripping encoded payloads
    4. Enforcing input length limits
    5. Wrapping input in safe delimiters
    """

    def __init__(
        self,
        max_length: int = 4096,
        allow_markdown: bool = True,
        safe_wrap: bool = True,
    ):
        self.max_length = max_length
        self.allow_markdown = allow_markdown
        self.safe_wrap = safe_wrap

    # ─────────────────────────────────────────
    # Sanitization Steps
    # ─────────────────────────────────────────

    def _strip_prompt_delimiters(self, text: str) -> Tuple[str, List[str]]:
        """Remove known LLM prompt injection delimiters."""
        mods = []
        patterns = [
            # OpenAI ChatML style
            (r'<\|im_start\|>.*?<\|im_end\|>', '[REDACTED_CHATML]'),
            # Llama/HF instruction tags
            (r'\[INST\].*?\[/INST\]', '[REDACTED_INST]'),
            (r'<<SYS>>.*?<</SYS>>', '[REDACTED_SYS]'),
            # XML-style role tags
            (r'<(system|assistant|user|instruction)[^>]*>.*?</(system|assistant|user|instruction)>', '[REDACTED_TAG]'),
            # Markdown code block injection
            (r'```\s*(system|assistant|instruction)\s*\n.*?```', '[REDACTED_BLOCK]', re.DOTALL),
        ]
        for item in patterns:
            pattern, replacement = item[0], item[1]
            flags = item[2] if len(item) > 2 else re.IGNORECASE | re.DOTALL
            new_text = re.sub(pattern, replacement, text, flags=flags)
            if new_text != text:
                mods.append(f"Stripped prompt delimiter: {pattern[:40]}")
                text = new_text
        return text, mods

    def _neutralize_overrides(self, text: str) -> Tuple[str, List[str]]:
        """Reframe known override phrases to be harmless."""
        mods = []
        overrides = [
            # "Ignore previous instructions" variants
            (r'\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|your)?\s*(instructions?|rules?|prompts?|guidelines?|constraints?)\b',
             '[instruction-override-attempt]'),
            # "You are now X with no restrictions"
            (r'\byou\s+are\s+now\s+\w[\w\s]{0,40}(no\s+(restrictions?|limits?|rules?|ethics?))',
             '[persona-override-attempt]'),
            # "Act as DAN / jailbreak"
            (r'\b(act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+.{0,60}(no\s+(restrictions?|safety|filter))',
             '[roleplay-jailbreak-attempt]'),
            # "Enable developer/jailbreak mode"
            (r'\benable\s+(developer|debug|jailbreak|unrestricted|god)\s+mode\b',
             '[mode-override-attempt]'),
            # DAN / explicit jailbreak names
            (r'\b(DAN|do\s+anything\s+now|jailbreak(ed)?)\b',
             '[jailbreak-keyword]'),
        ]
        for pattern, replacement in overrides:
            new_text = re.sub(pattern, replacement, text, flags=re.IGNORECASE | re.DOTALL)
            if new_text != text:
                mods.append(f"Neutralized override: {replacement}")
                text = new_text
        return text, mods

    def _handle_encoding(self, text: str) -> Tuple[str, List[str]]:
        """Flag and strip suspicious encoded content."""
        mods = []
        # Detect base64-like blobs (long strings of base64 chars)
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')
        if b64_pattern.search(text):
            text = b64_pattern.sub('[BASE64_BLOB_REMOVED]', text)
            mods.append("Removed potential base64 payload")

        # HTML entity injection
        decoded = html.unescape(text)
        if decoded != text:
            # Re-encode to neutralize HTML injection
            text = html.escape(decoded)
            mods.append("Re-escaped HTML entities")

        return text, mods

    def _enforce_length(self, text: str) -> Tuple[str, List[str]]:
        mods = []
        if len(text) > self.max_length:
            text = text[:self.max_length] + "\n[INPUT TRUNCATED]"
            mods.append(f"Input truncated to {self.max_length} chars")
        return text, mods

    def _safe_wrap_input(self, text: str) -> str:
        """
        Wrap the sanitized user input in clear delimiters so the LLM
        knows exactly where user content begins and ends.
        This makes it much harder for injected text to masquerade as
        system instructions.
        """
        return (
            "--- BEGIN USER INPUT ---\n"
            f"{text}\n"
            "--- END USER INPUT ---"
        )

    # ─────────────────────────────────────────
    # Main Entry Point
    # ─────────────────────────────────────────

    def sanitize(self, user_input: str) -> SanitizationResult:
        text = user_input
        all_mods = []

        text, mods = self._strip_prompt_delimiters(text)
        all_mods.extend(mods)

        text, mods = self._neutralize_overrides(text)
        all_mods.extend(mods)

        text, mods = self._handle_encoding(text)
        all_mods.extend(mods)

        text, mods = self._enforce_length(text)
        all_mods.extend(mods)

        if self.safe_wrap:
            text = self._safe_wrap_input(text)

        return SanitizationResult(
            original=user_input,
            sanitized=text,
            modifications=all_mods,
            was_modified=len(all_mods) > 0,
        )