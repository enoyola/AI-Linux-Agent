"""LLM integration clients with strict schema validation and safe fallbacks."""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any

from pydantic import TypeAdapter, ValidationError

from storai.detectors.cleanup import build_cleanup_advice
from storai.models import AdviceBundle, Plan
from storai.safety import allowlist_table


class LLMOutputError(RuntimeError):
    """Raised when model output is invalid or missing."""


class LLMClient(ABC):
    @abstractmethod
    def generate_advice(self, context: dict[str, Any]) -> AdviceBundle:
        raise NotImplementedError

    @abstractmethod
    def generate_plan(self, context: dict[str, Any], goal: str) -> Plan:
        raise NotImplementedError

    @abstractmethod
    def explain_findings(self, context: dict[str, Any]) -> str:
        raise NotImplementedError


class OfflineRulesClient(LLMClient):
    """Deterministic non-network planner/advisor."""

    def generate_advice(self, context: dict[str, Any]) -> AdviceBundle:
        space = context.get("space_analysis_obj")
        if space is None:
            return AdviceBundle(summary="No space analysis provided.", items=[], findings=context, source="offline")
        return build_cleanup_advice(space)

    def generate_plan(self, context: dict[str, Any], goal: str) -> Plan:
        # The mount workflow plan is constructed by Planner itself.
        return Plan(goal=goal, steps=[], warnings=["Offline rules do not auto-generate arbitrary plans."], source="offline")

    def explain_findings(self, context: dict[str, Any]) -> str:
        top = context.get("space_analysis", {}).get("top_dirs", [])
        if not top:
            return "No major space consumers detected from current context."
        first = top[0]
        return f"Largest path observed is {first.get('path')} at about {first.get('bytes_used', 0)} bytes."


class _JSONLLMBase(LLMClient):
    advice_adapter = TypeAdapter(AdviceBundle)
    plan_adapter = TypeAdapter(Plan)

    @staticmethod
    def _safe_context(context: dict[str, Any]) -> dict[str, Any]:
        # Drop non-serializable helper object used by offline rules.
        sanitized = {k: v for k, v in context.items() if k != "space_analysis_obj"}
        return json.loads(json.dumps(sanitized, default=str))

    def _advice_prompt(self, context: dict[str, Any]) -> str:
        schema = {
            "summary": "string",
            "items": [
                {
                    "category": "SAFE|CAUTION|REVIEW|DANGEROUS",
                    "title": "string",
                    "reasoning": "string",
                    "estimated_reclaim_gb": "number|null",
                    "commands": ["string"],
                }
            ],
            "findings": {"any": "object"},
            "source": "ai",
        }
        example = {
            "summary": "Space pressure mostly from logs and container layers.",
            "items": [
                {
                    "category": "SAFE",
                    "title": "Vacuum journal logs",
                    "reasoning": "journald files are large and old.",
                    "estimated_reclaim_gb": 3.2,
                    "commands": ["sudo journalctl --vacuum-time=7d"],
                }
            ],
            "findings": {},
            "source": "ai",
        }
        return (
            "Return JSON only. No markdown.\n"
            f"Allowed commands list: {allowlist_table()}\n"
            "Never include commands outside that allowlist.\n"
            f"Schema: {json.dumps(schema)}\n"
            f"Example: {json.dumps(example)}\n"
            f"Context JSON: {json.dumps(self._safe_context(context))}"
        )

    def _plan_prompt(self, context: dict[str, Any], goal: str) -> str:
        schema = {
            "goal": "string",
            "steps": [
                {
                    "id": "string",
                    "title": "string",
                    "rationale": "string",
                    "risk": "low|medium|high|critical",
                    "commands": [
                        {
                            "command": "string",
                            "args": ["string"],
                            "rationale": "string",
                            "read_only": "bool",
                            "requires_root": "bool",
                        }
                    ],
                }
            ],
            "warnings": ["string"],
            "rollback": ["string"],
            "requires_confirmation_string": "string|null",
            "source": "ai",
        }
        return (
            "Return JSON only. No markdown.\n"
            f"Goal: {goal}\n"
            f"Allowed commands list: {allowlist_table()}\n"
            "Never include commands outside that allowlist.\n"
            f"Schema: {json.dumps(schema)}\n"
            f"Context JSON: {json.dumps(self._safe_context(context))}"
        )

    def _parse_advice(self, text: str) -> AdviceBundle:
        try:
            payload = json.loads(text)
            data = self.advice_adapter.validate_python(payload)
            data.source = "ai"
            return data
        except (json.JSONDecodeError, ValidationError) as exc:
            raise LLMOutputError(f"Invalid advice JSON from model: {exc}") from exc

    def _parse_plan(self, text: str) -> Plan:
        try:
            payload = json.loads(text)
            data = self.plan_adapter.validate_python(payload)
            data.source = "ai"
            return data
        except (json.JSONDecodeError, ValidationError) as exc:
            raise LLMOutputError(f"Invalid plan JSON from model: {exc}") from exc


class OpenAIClient(_JSONLLMBase):
    def __init__(self, model: str | None = None, temperature: float = 0.2, max_tokens: int = 1200) -> None:
        self.model = model or "gpt-4o-mini"
        self.temperature = temperature
        self.max_tokens = max_tokens
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise LLMOutputError("OPENAI_API_KEY is not set")
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover - import-time environment difference
            raise LLMOutputError("openai package not installed. Install with storai[ai].") from exc
        self._client = OpenAI(api_key=api_key)

    def _chat(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        content = resp.choices[0].message.content or ""
        return content.strip()

    def generate_advice(self, context: dict[str, Any]) -> AdviceBundle:
        return self._parse_advice(self._chat(self._advice_prompt(context)))

    def generate_plan(self, context: dict[str, Any], goal: str) -> Plan:
        return self._parse_plan(self._chat(self._plan_prompt(context, goal)))

    def explain_findings(self, context: dict[str, Any]) -> str:
        prompt = "Explain findings in plain English in <= 120 words.\n" + json.dumps(self._safe_context(context))
        return self._chat(prompt)


class AnthropicClient(_JSONLLMBase):
    def __init__(self, model: str | None = None, temperature: float = 0.2, max_tokens: int = 1200) -> None:
        self.model = model or "claude-3-5-sonnet-20241022"
        self.temperature = temperature
        self.max_tokens = max_tokens
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise LLMOutputError("ANTHROPIC_API_KEY is not set")
        try:
            import anthropic
        except Exception as exc:  # pragma: no cover - import-time environment difference
            raise LLMOutputError("anthropic package not installed. Install with storai[ai].") from exc
        self._client = anthropic.Anthropic(api_key=api_key)

    def _chat(self, prompt: str) -> str:
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        chunks = [getattr(part, "text", "") for part in msg.content]
        return "".join(chunks).strip()

    def generate_advice(self, context: dict[str, Any]) -> AdviceBundle:
        return self._parse_advice(self._chat(self._advice_prompt(context)))

    def generate_plan(self, context: dict[str, Any], goal: str) -> Plan:
        return self._parse_plan(self._chat(self._plan_prompt(context, goal)))

    def explain_findings(self, context: dict[str, Any]) -> str:
        prompt = "Explain findings in plain English in <= 120 words.\n" + json.dumps(self._safe_context(context))
        return self._chat(prompt)
