import json
from typing import Any, Protocol, cast

from openai import AsyncOpenAI, OpenAIError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from clicksafe.core.config import Settings, get_settings
from clicksafe.domain.enums import Verdict


class ResponsesResource(Protocol):
    async def create(self, **kwargs: Any) -> Any:
        ...


class OpenAIClientLike(Protocol):
    responses: ResponsesResource


class EvidenceWeight(BaseModel):
    source: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    weight: int = Field(ge=0, le=100)
    reason: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


class AIVerdict(BaseModel):
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    explanation: str = Field(min_length=1)
    recommended_action: str = Field(min_length=1)
    evidence_weights: list[EvidenceWeight] = Field(min_length=1, max_length=12)

    model_config = ConfigDict(extra="forbid", use_enum_values=True)


AI_VERDICT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "risk_score",
        "confidence",
        "explanation",
        "recommended_action",
        "evidence_weights",
    ],
    "properties": {
        "verdict": {"type": "string", "enum": ["Safe", "Suspicious", "Malicious"]},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "explanation": {"type": "string"},
        "recommended_action": {"type": "string"},
        "evidence_weights": {
            "type": "array",
            "minItems": 1,
            "maxItems": 12,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["source", "severity", "weight", "reason"],
                "properties": {
                    "source": {"type": "string"},
                    "severity": {"type": "string"},
                    "weight": {"type": "integer", "minimum": 0, "maximum": 100},
                    "reason": {"type": "string"},
                },
            },
        },
    },
}

SYSTEM_INSTRUCTIONS = """You are ClickSafe's phishing risk analyst.
Classify the submitted URL as Safe, Suspicious, or Malicious using only the supplied evidence.
Risk score guidance: 0-30 Safe, 31-69 Suspicious, 70-100 Malicious.
Treat browser failures, credential forms, insecure form actions, hidden redirects, recent domains,
TLS failures, reputation hits, and obfuscated JavaScript as meaningful risk signals.
Do not claim certainty beyond the evidence. Keep the explanation concise and evidence-grounded."""

SEVERITY_SCORES = {
    "info": 8,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 92,
}


class OpenAIResponsesClient:
    def __init__(
        self,
        settings: Settings | None = None,
        client: OpenAIClientLike | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client
        if self._client is None and self._settings.openai_api_key:
            self._client = cast(
                OpenAIClientLike,
                AsyncOpenAI(
                    api_key=self._settings.openai_api_key,
                    timeout=self._settings.openai_timeout_seconds,
                ),
            )

    async def assess(self, evidence: dict[str, Any]) -> dict[str, Any]:
        if not self._settings.openai_api_key and self._client is None:
            return self._fallback_assessment(
                evidence,
                status="skipped",
                reason="missing_api_key",
            )

        if self._client is None:
            return self._fallback_assessment(
                evidence,
                status="unavailable",
                reason="client_not_configured",
            )

        try:
            response = await self._client.responses.create(
                model=self._settings.openai_model,
                instructions=SYSTEM_INSTRUCTIONS,
                input=self._build_input(evidence),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "clicksafe_ai_verdict",
                        "strict": True,
                        "schema": AI_VERDICT_JSON_SCHEMA,
                    }
                },
                reasoning={"effort": self._settings.openai_reasoning_effort},
                max_output_tokens=self._settings.openai_max_output_tokens,
                store=False,
            )
            verdict = AIVerdict.model_validate_json(cast(str, response.output_text))
            return self._serialize_verdict(
                verdict,
                enabled=True,
                status="completed",
                fallback_used=False,
                model=self._settings.openai_model,
                response_id=cast(str | None, getattr(response, "id", None)),
            )
        except (OpenAIError, ValidationError, json.JSONDecodeError, AttributeError) as exc:
            return self._fallback_assessment(
                evidence,
                status="fallback",
                reason=type(exc).__name__,
            )

    def _build_input(self, evidence: dict[str, Any]) -> str:
        compact_evidence = json.dumps(
            evidence,
            ensure_ascii=True,
            sort_keys=True,
            default=str,
        )
        return (
            "Analyze this URL evidence bundle and return the strict JSON verdict.\n"
            f"{compact_evidence}"
        )

    def _fallback_assessment(
        self,
        evidence: dict[str, Any],
        *,
        status: str,
        reason: str,
    ) -> dict[str, Any]:
        evidence_weights = self._heuristic_evidence_weights(evidence)
        risk_score = max(item.weight for item in evidence_weights)
        if self._has_reputation_hit(evidence):
            risk_score = max(risk_score, 92)
        elif self._has_browser_failure(evidence):
            risk_score = max(risk_score, 65)

        verdict = self._verdict_from_score(risk_score)
        explanation = self._fallback_explanation(verdict, reason, evidence_weights)
        ai_verdict = AIVerdict(
            verdict=verdict,
            risk_score=risk_score,
            confidence=0.55,
            explanation=explanation,
            recommended_action=self._recommended_action(verdict),
            evidence_weights=evidence_weights[:12],
        )
        return self._serialize_verdict(
            ai_verdict,
            enabled=False,
            status=status,
            fallback_used=True,
            model=self._settings.openai_model,
            response_id=None,
            reason=reason,
        )

    def _heuristic_evidence_weights(self, evidence: dict[str, Any]) -> list[EvidenceWeight]:
        items: list[EvidenceWeight] = []
        for section_name in ("technical_analysis", "reputation"):
            section = evidence.get(section_name)
            if not isinstance(section, list):
                continue
            for raw_item in section:
                if not isinstance(raw_item, dict):
                    continue
                severity = str(raw_item.get("severity") or "info")
                items.append(
                    EvidenceWeight(
                        source=str(raw_item.get("source") or section_name),
                        severity=severity,
                        weight=SEVERITY_SCORES.get(severity, 20),
                        reason=str(raw_item.get("title") or "Evidence item observed."),
                    )
                )

        if not items:
            items.append(
                EvidenceWeight(
                    source="baseline",
                    severity="info",
                    weight=15,
                    reason="No high-risk technical or reputation evidence was available.",
                )
            )

        return sorted(items, key=lambda item: item.weight, reverse=True)

    def _has_reputation_hit(self, evidence: dict[str, Any]) -> bool:
        reputation_items = evidence.get("reputation")
        if not isinstance(reputation_items, list):
            return False
        for item in reputation_items:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            if not isinstance(data, dict):
                continue
            virustotal = data.get("virustotal")
            safe_browsing = data.get("google_safe_browsing")
            if isinstance(virustotal, dict) and int(virustotal.get("malicious") or 0) > 0:
                return True
            if isinstance(safe_browsing, dict) and bool(safe_browsing.get("listed")):
                return True
        return False

    def _has_browser_failure(self, evidence: dict[str, Any]) -> bool:
        browser = evidence.get("browser")
        return isinstance(browser, dict) and browser.get("captured") is False

    def _verdict_from_score(self, risk_score: int) -> Verdict:
        if risk_score >= 70:
            return Verdict.MALICIOUS
        if risk_score >= 31:
            return Verdict.SUSPICIOUS
        return Verdict.SAFE

    def _recommended_action(self, verdict: Verdict | str) -> str:
        if verdict == Verdict.MALICIOUS or verdict == Verdict.MALICIOUS.value:
            return "Do not visit this URL. Treat it as dangerous."
        if verdict == Verdict.SUSPICIOUS or verdict == Verdict.SUSPICIOUS.value:
            return "Avoid entering credentials or sensitive data unless manually verified."
        return "No strong phishing indicators were found, but continue using normal caution."

    def _fallback_explanation(
        self,
        verdict: Verdict,
        reason: str,
        evidence_weights: list[EvidenceWeight],
    ) -> str:
        strongest = evidence_weights[0]
        return (
            f"OpenAI assessment was not completed ({reason}), so ClickSafe used local "
            f"evidence weighting. The strongest signal was {strongest.source} "
            f"({strongest.severity})."
        )

    def _serialize_verdict(
        self,
        verdict: AIVerdict,
        *,
        enabled: bool,
        status: str,
        fallback_used: bool,
        model: str,
        response_id: str | None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "provider": "openai_responses",
            "enabled": enabled,
            "status": status,
            "fallback_used": fallback_used,
            "model": model,
            "response_id": response_id,
            "reason": reason,
            **verdict.model_dump(mode="json"),
        }
