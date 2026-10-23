import json
import logging
from typing import Any

import httpx
import pytest
from openai import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    RateLimitError,
)

from clicksafe.core.config import Settings
from clicksafe.core.logging import JsonFormatter
from clicksafe.infrastructure.ai.openai_responses_client import OpenAIResponsesClient


class FakeResponse:
    id = "resp_test"
    output_text = json.dumps(
        {
            "verdict": "Malicious",
            "risk_score": 91,
            "confidence": 0.86,
            "explanation": "Reputation and form evidence indicate credential theft risk.",
            "recommended_action": "Do not visit this URL.",
            "evidence_weights": [
                {
                    "source": "reputation",
                    "severity": "critical",
                    "weight": 91,
                    "reason": "A reputation provider listed the URL.",
                }
            ],
        }
    )


class FakeResponsesResource:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.response


class FakeOpenAIClient:
    def __init__(self, response: Any) -> None:
        self.responses = FakeResponsesResource(response)


async def test_assess_uses_responses_api_structured_outputs() -> None:
    fake_client = FakeOpenAIClient(FakeResponse())
    client = OpenAIResponsesClient(
        Settings(openai_api_key="test-key", openai_model="gpt-test"),
        client=fake_client,
    )

    result = await client.assess(
        {
            "technical_analysis": [],
            "reputation": [],
            "ml_analysis": {
                "model_available": True,
                "predicted_label": "legitimate",
                "phishing_probability": 0.01,
            },
        }
    )

    assert result["enabled"] is True
    assert result["status"] == "completed"
    assert result["fallback_used"] is False
    assert result["verdict"] == "Malicious"
    assert result["risk_score"] == 91
    assert result["response_id"] == "resp_test"
    assert result["reason"] is None
    call = fake_client.responses.calls[0]
    assert call["model"] == "gpt-test"
    assert call["store"] is False
    assert "Do not set the final verdict from that classifier alone." in call["instructions"]
    assert call["text"]["format"]["type"] == "json_schema"
    assert call["text"]["format"]["strict"] is True
    assert call["text"]["format"]["name"] == "clicksafe_ai_verdict"


async def test_gpt_5_4_mini_success_keeps_the_model_verdict() -> None:
    fake_client = FakeOpenAIClient(FakeResponse())
    client = OpenAIResponsesClient(
        Settings(
            openai_api_key="test-key",
            openai_model="gpt-5.4-mini",
            openai_reasoning_effort="medium",
        ),
        client=fake_client,
    )

    result = await client.assess(
        {
            "technical_analysis": [
                {"source": "html", "severity": "info", "title": "Page title"},
            ],
            "ml_analysis": {
                "model_available": True,
                "predicted_label": "malicious",
                "phishing_probability": 0.99,
            },
        }
    )

    call = fake_client.responses.calls[0]
    assert call["model"] == "gpt-5.4-mini"
    assert call["reasoning"] == {"effort": "medium"}
    assert call["text"]["format"]["strict"] is True
    assert call["store"] is False
    assert result["status"] == "completed"
    assert result["fallback_used"] is False
    assert result["model"] == "gpt-5.4-mini"
    assert result["verdict"] == "Malicious"
    assert result["risk_score"] == 91


async def test_missing_openai_key_uses_transparent_fallback() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))

    result = await client.assess({"technical_analysis": [], "reputation": []})

    assert result["enabled"] is False
    assert result["fallback_used"] is True
    assert result["reason"] == "missing_api_key"
    assert result["verdict"] == "Safe"


async def test_fallback_does_not_let_the_classifier_set_the_verdict() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))
    evidence = {
        "technical_analysis": [
            {
                "source": "html",
                "severity": "info",
                "title": "Page title",
            }
        ],
        "reputation": [],
        "ml_analysis": {
            "predicted_label": "malicious",
            "phishing_probability": 0.99,
            "probabilities_calibrated": False,
        },
    }

    result = await client.assess(evidence)

    assert result["verdict"] == "Safe"
    assert result["risk_score"] == 8
    ml_items = [item for item in result["evidence_weights"] if item["source"] == "ml_analysis"]
    assert len(ml_items) == 1
    assert ml_items[0]["weight"] <= 8
    assert "did not set the verdict by itself" in result["explanation"]


async def test_fallback_marks_reputation_hits_malicious() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))
    evidence = {
        "reputation": [
            {
                "source": "reputation",
                "severity": "info",
                "data": {
                    "virustotal": {"malicious": 1},
                    "google_safe_browsing": {"listed": False},
                },
            }
        ]
    }

    result = await client.assess(evidence)

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] == 92


async def test_invalid_model_output_falls_back() -> None:
    class InvalidResponse:
        id = "resp_invalid"
        output_text = "{}"

    client = OpenAIResponsesClient(
        Settings(openai_api_key="test-key"),
        client=FakeOpenAIClient(InvalidResponse()),
    )

    result = await client.assess({"technical_analysis": [], "reputation": []})

    assert result["enabled"] is False
    assert result["fallback_used"] is True
    assert result["status"] == "fallback"
    assert result["reason"] == "invalid_response"


class RaisingResponses:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        raise self.exc


class RaisingClient:
    def __init__(self, exc: Exception) -> None:
        self.responses = RaisingResponses(exc)


def _api_response(status: int) -> httpx.Response:
    request = httpx.Request(
        "POST",
        "https://api.openai.com/v1/responses",
        headers={"Authorization": "Bearer sk-testsecretvalue"},
    )
    return httpx.Response(status, request=request)


def _client(exc: Exception, model: str = "gpt-5.4-mini") -> OpenAIResponsesClient:
    return OpenAIResponsesClient(
        Settings(
            openai_api_key="test-key",
            openai_model=model,
            openai_reasoning_effort="medium",
        ),
        client=RaisingClient(exc),
    )


def _info_evidence() -> dict[str, Any]:
    return {
        "technical_analysis": [
            {"source": "html", "severity": "info", "title": "Page title"},
        ],
        "reputation": [],
    }


async def _assess_failure(exc: Exception) -> dict[str, Any]:
    client = _client(exc)
    result = await client.assess(_info_evidence())
    call = client._client.responses.calls[0]
    assert call["model"] == "gpt-5.4-mini"
    assert call["reasoning"] == {"effort": "medium"}
    assert call["text"]["format"]["type"] == "json_schema"
    assert call["text"]["format"]["strict"] is True
    assert call["text"]["format"]["name"] == "clicksafe_ai_verdict"
    assert result["model"] == "gpt-5.4-mini"
    assert result["status"] == "fallback"
    assert result["fallback_used"] is True
    assert result["enabled"] is False
    assert "sk-testsecretvalue" not in json.dumps(result)
    return result


async def test_quota_error_uses_fallback_and_keeps_the_configured_model(
    caplog: pytest.LogCaptureFixture,
) -> None:
    exc = RateLimitError(
        "You have no credits remaining. Add credits to continue using the API.",
        response=_api_response(429),
        body={
            "message": "You have no credits remaining. Add credits to continue using the API.",
            "type": "insufficient_quota",
            "code": "credit_balance_exhausted",
            "param": None,
        },
    )

    with caplog.at_level(logging.WARNING):
        result = await _assess_failure(exc)

    assert result["reason"] == "quota_error"
    assert result["verdict"] == "Safe"
    assert result["risk_score"] == 8
    payload = _formatted_log(caplog)
    assert payload["openai_error_category"] == "quota_error"
    assert payload["openai_error_type"] == "RateLimitError"
    assert payload["openai_status_code"] == 429
    assert payload["openai_error_code"] == "credit_balance_exhausted"
    assert payload.get("exception") is None
    assert "sk-testsecretvalue" not in json.dumps(payload)
    assert "Authorization" not in json.dumps(payload)


async def test_nested_quota_body_is_classified_without_the_sdk_flattening() -> None:
    exc = RateLimitError(
        "Billing is unavailable.",
        response=_api_response(429),
        body={
            "error": {
                "message": "Billing is unavailable.",
                "type": "insufficient_quota",
                "code": "credit_balance_exhausted",
            }
        },
    )

    result = await _assess_failure(exc)

    assert result["reason"] == "quota_error"


async def test_rate_limit_without_quota_keeps_a_distinct_reason() -> None:
    exc = RateLimitError(
        "Rate limit reached for requests.",
        response=_api_response(429),
        body={
            "message": "Rate limit reached for requests.",
            "type": "requests",
            "code": "rate_limit_exceeded",
        },
    )

    result = await _assess_failure(exc)

    assert result["reason"] == "rate_limit_error"


async def test_authentication_error_is_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "sk-testsecretvalue"
    exc = AuthenticationError(
        f"Incorrect API key provided: {secret}. api_key={secret}",
        response=_api_response(401),
        body={
            "message": f"Incorrect API key provided: {secret}. api_key={secret}",
            "type": "invalid_request_error",
            "code": "invalid_api_key",
        },
    )

    with caplog.at_level(logging.WARNING):
        result = await _assess_failure(exc)

    assert result["reason"] == "authentication_error"
    payload = _formatted_log(caplog)
    rendered = json.dumps(payload)
    assert payload["openai_error_category"] == "authentication_error"
    assert payload["openai_status_code"] == 401
    assert "sk-redacted" in rendered
    assert secret not in rendered
    assert "Authorization" not in rendered
    assert secret not in caplog.text


async def test_invalid_model_error_does_not_change_the_model() -> None:
    exc = BadRequestError(
        "The model `gpt-5.4-mini` does not exist or you do not have access to it.",
        response=_api_response(400),
        body={
            "message": "The model `gpt-5.4-mini` does not exist or you do not have access to it.",
            "type": "invalid_request_error",
            "param": "model",
            "code": "model_not_found",
        },
    )

    result = await _assess_failure(exc)

    assert result["reason"] == "invalid_model"
    assert result["model"] == "gpt-5.4-mini"


async def test_not_found_model_error_is_invalid_model() -> None:
    exc = NotFoundError(
        "The model `gpt-5.4-mini` does not exist.",
        response=_api_response(404),
        body={
            "message": "The model `gpt-5.4-mini` does not exist.",
            "type": "invalid_request_error",
            "code": "model_not_found",
        },
    )

    result = await _assess_failure(exc)

    assert result["reason"] == "invalid_model"


async def test_non_model_bad_request_is_invalid_request() -> None:
    exc = BadRequestError(
        "Invalid schema for response format.",
        response=_api_response(400),
        body={
            "message": "Invalid schema for response format.",
            "type": "invalid_request_error",
            "code": "invalid_json_schema",
        },
    )

    result = await _assess_failure(exc)

    assert result["reason"] == "invalid_request"


async def test_timeout_and_connection_errors_are_classified() -> None:
    request = _api_response(500).request
    timeout = await _assess_failure(APITimeoutError(request))
    connection = await _assess_failure(
        APIConnectionError(message="Connection error.", request=request)
    )

    assert timeout["reason"] == "timeout"
    assert connection["reason"] == "connection_error"


async def test_empty_model_output_is_an_invalid_response() -> None:
    class EmptyResponse:
        id = "resp_empty"
        output_text = ""

    client = OpenAIResponsesClient(
        Settings(openai_api_key="test-key", openai_model="gpt-5.4-mini"),
        client=FakeOpenAIClient(EmptyResponse()),
    )

    result = await client.assess(_info_evidence())

    assert result["reason"] == "invalid_response"
    assert result["fallback_used"] is True
    assert result["model"] == "gpt-5.4-mini"


async def test_fallback_reinforces_suspicious_evidence_with_ml() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))
    evidence = {
        "technical_analysis": [
            {"source": "forms", "severity": "medium", "title": "Credential form"},
        ],
        "ml_analysis": {
            "model_available": True,
            "predicted_label": "malicious",
            "phishing_probability": 0.99,
        },
    }

    result = await client.assess(evidence)

    assert result["verdict"] == "Suspicious"
    assert result["risk_score"] == 60
    ml_items = [item for item in result["evidence_weights"] if item["source"] == "ml_analysis"]
    assert ml_items[0]["weight"] <= 50
    assert "forms" in result["explanation"]


async def test_fallback_suspicious_label_adds_a_smaller_amount() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))
    evidence = {
        "technical_analysis": [
            {"source": "javascript", "severity": "medium", "title": "Obfuscated script"},
        ],
        "ml_analysis": {"predicted_label": "suspicious", "phishing_probability": 0.4},
    }

    result = await client.assess(evidence)

    assert result["verdict"] == "Suspicious"
    assert result["risk_score"] == 55


async def test_fallback_does_not_let_ml_lower_or_create_malicious() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))
    high = {
        "technical_analysis": [
            {"source": "ssl", "severity": "high", "title": "Certificate failed"},
        ],
        "ml_analysis": {"predicted_label": "legitimate", "phishing_probability": 0.01},
    }
    browser = {
        "technical_analysis": [
            {"source": "html", "severity": "info", "title": "Page title"},
        ],
        "browser": {"captured": False},
        "ml_analysis": {"predicted_label": "malicious", "phishing_probability": 0.99},
    }

    high_result = await client.assess(high)
    browser_result = await client.assess(browser)

    assert high_result["verdict"] == "Malicious"
    assert high_result["risk_score"] == 75
    assert browser_result["verdict"] == "Suspicious"
    assert browser_result["risk_score"] == 69


async def test_reputation_hit_stays_malicious_when_ml_says_legitimate() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))
    evidence = {
        "reputation": [
            {
                "source": "reputation",
                "severity": "info",
                "data": {"google_safe_browsing": {"listed": True}},
            }
        ],
        "ml_analysis": {"predicted_label": "legitimate", "phishing_probability": 0.0},
    }

    result = await client.assess(evidence)

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] == 92


async def test_ml_alone_stays_inside_the_safe_band() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))
    alone = await client.assess(
        {
            "ml_analysis": {
                "predicted_label": "malicious",
                "phishing_probability": 0.99,
            }
        }
    )
    unavailable = await client.assess(
        {
            "technical_analysis": [
                {"source": "html", "severity": "info", "title": "Page title"},
            ],
            "ml_analysis": {
                "model_available": False,
                "predicted_label": "malicious",
                "phishing_probability": 0.99,
            },
        }
    )

    assert alone["verdict"] == "Safe"
    assert alone["risk_score"] == 15
    assert any(item["source"] == "ml_analysis" for item in alone["evidence_weights"])
    assert unavailable["verdict"] == "Safe"
    assert unavailable["risk_score"] == 8
    assert all(item["source"] != "ml_analysis" for item in unavailable["evidence_weights"])


def _formatted_log(caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    matches = [
        record
        for record in caplog.records
        if getattr(record, "event", None) == "openai.assessment_failed"
    ]
    assert len(matches) == 1
    record = matches[0]
    assert record.exc_info is None
    payload = json.loads(JsonFormatter().format(record))
    assert isinstance(payload, dict)
    return payload
