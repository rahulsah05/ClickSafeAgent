import json
import logging
import re
from typing import Any, Protocol, cast

from openai import (
    APIConnectionError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    OpenAIError,
    RateLimitError,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from clicksafe.core.config import Settings, get_settings
from clicksafe.domain.enums import Verdict

logger = logging.getLogger(__name__)
_SECRET_RE = re.compile(r"sk-[A-Za-z0-9_\-]{6,}")
_QUOTA_CODES = {"insufficient_quota", "credit_balance_exhausted"}


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
URL pre-scan keywords such as login, account, secure, and payment are evidence only.
Do not classify a URL as malicious from those words alone.
ml_analysis is one local structured-URL classifier signal. It includes predicted_label,
an uncalibrated phishing_probability, a matched brand, and detected transformations.
Do not set the final verdict from that classifier alone.
A malicious or suspicious predicted_label does not override contradictory evidence
from the browser, HTML, DNS, SSL, WHOIS, or reputation checks.
A legitimate predicted_label does not override those checks either.
Do not claim certainty beyond the evidence. Keep the explanation concise and evidence-grounded."""

SEVERITY_SCORES = {
    "info": 8,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 92,
}
_ML_LABELS = {"legitimate", "suspicious", "malicious"}


class MlSignal:
    def __init__(self, label: str, item: EvidenceWeight) -> None:
        self.label = label
        self.item = item


def classify_openai_failure(exc: Exception) -> str:
    """Map a provider or parse failure to a stable category. The key is not included."""

    if isinstance(exc, APITimeoutError):
        return "timeout"
    if isinstance(exc, APIConnectionError):
        return "connection_error"
    if isinstance(exc, AuthenticationError):
        return "authentication_error"
    if isinstance(exc, NotFoundError) or (
        isinstance(exc, BadRequestError) and _mentions_model(exc)
    ):
        return "invalid_model"
    if isinstance(exc, BadRequestError):
        return "invalid_request"
    if isinstance(exc, RateLimitError):
        return "quota_error" if _is_quota_error(exc) else "rate_limit_error"
    if isinstance(exc, (ValidationError, json.JSONDecodeError, AttributeError)):
        return "invalid_response"
    return "api_error"


def _error_parts(exc: Exception) -> tuple[str, str, str, str]:
    code = str(getattr(exc, "code", "") or "")
    api_type = str(getattr(exc, "type", "") or "")
    param = str(getattr(exc, "param", "") or "")
    message = str(getattr(exc, "message", "") or "")
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        nested = body.get("error")
        source = nested if isinstance(nested, dict) else body
        code = code or str(source.get("code") or "")
        api_type = api_type or str(source.get("type") or "")
        param = param or str(source.get("param") or "")
        message = message or str(source.get("message") or "")
    return code.lower(), api_type.lower(), param.lower(), message


def _mentions_model(exc: Exception) -> bool:
    code, _api_type, param, _message = _error_parts(exc)
    return param == "model" or code in {"model_not_found", "invalid_model"}


def _is_quota_error(exc: Exception) -> bool:
    code, api_type, _param, message = _error_parts(exc)
    lowered = message.lower()
    return (
        code in _QUOTA_CODES
        or api_type in _QUOTA_CODES
        or "quota" in code
        or "quota" in lowered
        or "no credits" in lowered
    )


def _redact(text: str) -> str:
    redacted = _SECRET_RE.sub("sk-redacted", text)
    return re.sub(r"(?i)(api[_-]?key['\"=: ]+)\S+", r"\1redacted", redacted)


def _log_openai_failure(exc: Exception, category: str) -> None:
    code, _api_type, _param, message = _error_parts(exc)
    safe_message = _redact(message)[:300]
    logger.warning(
        "OpenAI assessment failed (%s): %s",
        category,
        safe_message or type(exc).__name__,
        extra={
            "event": "openai.assessment_failed",
            "openai_error_category": category,
            "openai_error_type": type(exc).__name__,
            "openai_status_code": getattr(exc, "status_code", None),
            "openai_error_code": code or None,
        },
    )


def _ml_signal(raw: object) -> MlSignal | None:
    if not isinstance(raw, dict) or raw.get("model_available") is False:
        return None
    label = str(raw.get("predicted_label") or raw.get("predicted_class") or "")
    if label not in _ML_LABELS:
        return None
    suggested = {"legitimate": 8, "suspicious": 40, "malicious": 55}[label]
    probability = raw.get("phishing_probability")
    reason = f"Structured classifier predicted {label}."
    if isinstance(probability, (int, float)) and not isinstance(probability, bool):
        reason += f" Uncalibrated malicious probability: {float(probability):.2f}."
    reason += " This signal does not set the verdict by itself."
    return MlSignal(
        label,
        EvidenceWeight(
            source="ml_analysis",
            severity="info",
            weight=suggested,
            reason=reason,
        ),
    )


def _combine_ml_score(base: int, signal: MlSignal | None) -> int:
    """Reinforce an already elevated score. A classifier label cannot open a new band."""

    if signal is None or base < 31 or signal.label == "legitimate" or base >= 70:
        return base
    bump = 10 if signal.label == "malicious" else 5
    return min(69, base + bump)


def _display_ml_weight(signal: MlSignal, base: int) -> EvidenceWeight:
    visible = min(signal.item.weight, base)
    return signal.item.model_copy(update={"weight": visible})


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
            category = classify_openai_failure(exc)
            _log_openai_failure(exc, category)
            return self._fallback_assessment(
                evidence,
                status="fallback",
                reason=category,
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
        non_ml, ml_signal = self._heuristic_evidence_weights(evidence)
        base_score = max(item.weight for item in non_ml)
        if self._has_reputation_hit(evidence):
            base_score = max(base_score, 92)
        elif self._has_browser_failure(evidence):
            base_score = max(base_score, 65)
        risk_score = _combine_ml_score(base_score, ml_signal)
        evidence_weights = list(non_ml)
        if ml_signal is not None:
            evidence_weights.append(_display_ml_weight(ml_signal, base_score))
        evidence_weights = sorted(evidence_weights, key=lambda item: item.weight, reverse=True)

        verdict = self._verdict_from_score(risk_score)
        explanation = self._fallback_explanation(
            verdict,
            reason,
            non_ml,
            None if ml_signal is None else ml_signal.label,
        )
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

    def _heuristic_evidence_weights(
        self,
        evidence: dict[str, Any],
    ) -> tuple[list[EvidenceWeight], MlSignal | None]:
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

        return items, _ml_signal(evidence.get("ml_analysis"))

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
        ml_label: str | None,
    ) -> str:
        del verdict
        strongest = max(evidence_weights, key=lambda item: item.weight)
        text = (
            f"OpenAI assessment was not completed ({reason}), so ClickSafe used local "
            f"evidence weighting. The strongest non-classifier signal was {strongest.source} "
            f"({strongest.severity})."
        )
        if ml_label:
            text += (
                f" The structured classifier predicted {ml_label}. That prediction was "
                "combined with the other evidence and did not set the verdict by itself."
            )
        return text

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
