"""
PromptShield Python SDK
Usage:
    from promptshield_sdk import PromptShieldClient

    client = PromptShieldClient(api_key="ps_live_yourkey")

    # Chat
    result = client.chat("Hello!")
    print(result)

    # Analyze only (no LLM call)
    threat = client.analyze("Ignore previous instructions")
    print(threat)

    # Get stats
    stats = client.summary()
    print(stats)
"""

import requests
from typing import Optional


class PromptShieldError(Exception):
    pass


class PromptShieldClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://prompt-shield.onrender.com",
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self._headers = {
            "X-API-Key":    api_key,
            "Content-Type": "application/json",
        }

    def _post(self, endpoint: str, payload: dict) -> dict:
        try:
            res = requests.post(
                f"{self.base_url}{endpoint}",
                json=payload,
                headers=self._headers,
                timeout=self.timeout,
            )
            if res.status_code == 401:
                raise PromptShieldError("Invalid or missing API key.")
            if res.status_code == 429:
                raise PromptShieldError("Rate limit exceeded. Slow down requests.")
            if not res.ok:
                raise PromptShieldError(f"Request failed: {res.status_code} {res.text}")
            return res.json()
        except requests.exceptions.Timeout:
            raise PromptShieldError("Request timed out.")
        except requests.exceptions.ConnectionError:
            raise PromptShieldError("Could not connect to PromptShield.")

    def _get(self, endpoint: str) -> dict:
        try:
            res = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self._headers,
                timeout=self.timeout,
            )
            if not res.ok:
                raise PromptShieldError(f"Request failed: {res.status_code} {res.text}")
            return res.json()
        except requests.exceptions.Timeout:
            raise PromptShieldError("Request timed out.")

    def chat(self, message: str, session_id: Optional[str] = None) -> dict:
        """
        Send a message through PromptShield to the LLM.
        Returns full result including threat info.
        """
        return self._post("/chat", {"message": message, "session_id": session_id})

    def analyze(self, text: str) -> dict:
        """
        Analyze text for prompt injection threats without calling the LLM.
        """
        return self._post("/analyze", {"text": text})

    def set_aggression(self, level: str) -> dict:
        """
        Set aggression level: permissive | balanced | strict | paranoid
        """
        return self._post("/aggression", {"level": level})

    def stats(self) -> dict:
        """Get current shield configuration and thresholds."""
        return self._get("/stats")

    def logs(self, limit: int = 50) -> list:
        """Get recent audit log entries."""
        return self._get(f"/logs?limit={limit}").get("logs", [])

    def summary(self) -> dict:
        """Get summary stats — block rate, threat breakdown, etc."""
        return self._get("/logs/summary")

    def health(self) -> dict:
        """Check if the service is up."""
        return self._get("/health")