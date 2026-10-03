"""Provider abstraction and OpenAI Responses API implementation."""

from __future__ import annotations

import json
import os
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from analyzer.ai_schema import ANALYSIS_JSON_SCHEMA


SYSTEM_INSTRUCTIONS = """You are a cybersecurity behavior analyst reviewing an SSH honeypot session.
Analyze the ordered session as a whole; do not label a single command in isolation.
Separate observed facts from interpretations. Every fact and pattern must cite only
provided event IDs. Never invent events, detections, ATT&CK mappings, or outcomes.
State uncertainty explicitly, use low confidence when evidence is sparse, and do not
claim a real compromise or successful credential use from Cowrie simulation alone.
Recommend only one of: generic_linux, web_server, database_server, developer_workstation.
The profile is only a suggestion from fixed fictional choices. Return only the required
structured analysis. Do not propose or emit shell commands,
code, or actions for execution."""


class AIProviderError(RuntimeError):
    """Raised when a configured AI provider cannot complete an analysis request."""


class AIProvider(Protocol):
    def analyze(self, context: dict[str, Any]) -> str:
        """Return the provider's raw JSON response text."""


class OpenAIResponsesProvider:
    """Minimal OpenAI Responses API client using structured JSON output."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-6-astra")
        self.base_url = (base_url or os.getenv(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        )).rstrip("/")
        if timeout_seconds is None:
            try:
                timeout_seconds = float(os.getenv("AI_REQUEST_TIMEOUT_SECONDS", "30"))
            except ValueError as exc:
                raise ValueError("AI_REQUEST_TIMEOUT_SECONDS must be numeric") from exc
        if timeout_seconds <= 0:
            raise ValueError("AI request timeout must be positive")
        self.timeout_seconds = timeout_seconds

    def analyze(self, context: dict[str, Any]) -> str:
        if not self.api_key:
            raise AIProviderError("OPENAI_API_KEY is not configured.")

        body = {
            "model": self.model,
            "store": False,
            "max_output_tokens": 1600,
            "input": [
                {"role": "system", "content": SYSTEM_INSTRUCTIONS},
                {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "ssh_session_behavior_analysis",
                    "strict": True,
                    "schema": ANALYSIS_JSON_SCHEMA,
                }
            },
        }
        request = Request(
            f"{self.base_url}/responses",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise AIProviderError(f"OpenAI API returned HTTP {exc.code}.") from exc
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise AIProviderError("OpenAI API request failed.") from exc

        if payload.get("status") != "completed":
            raise AIProviderError("OpenAI response was not completed.")
        output_text: list[str] = []
        for item in payload.get("output", []):
            if item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if content.get("type") == "refusal":
                    raise AIProviderError("OpenAI declined the analysis request.")
                if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                    output_text.append(content["text"])
        if not output_text:
            raise AIProviderError("OpenAI response contained no structured text.")
        return "\n".join(output_text)


def provider_from_environment() -> AIProvider:
    provider_name = os.getenv("AI_PROVIDER", "openai").strip().lower()
    if provider_name == "openai":
        return OpenAIResponsesProvider()
    raise AIProviderError(f"Unsupported AI_PROVIDER: {provider_name or '(empty)'}")
