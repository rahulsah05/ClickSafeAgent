import json
from typing import Any

from clicksafe.core.config import Settings
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

    result = await client.assess({"technical_analysis": [], "reputation": []})

    assert result["enabled"] is True
    assert result["fallback_used"] is False
    assert result["verdict"] == "Malicious"
    assert result["risk_score"] == 91
    assert result["response_id"] == "resp_test"
    call = fake_client.responses.calls[0]
    assert call["model"] == "gpt-test"
    assert call["store"] is False
    assert call["text"]["format"]["type"] == "json_schema"
    assert call["text"]["format"]["strict"] is True


async def test_missing_openai_key_uses_transparent_fallback() -> None:
    client = OpenAIResponsesClient(Settings(openai_api_key=""))

    result = await client.assess({"technical_analysis": [], "reputation": []})

    assert result["enabled"] is False
    assert result["fallback_used"] is True
    assert result["reason"] == "missing_api_key"
    assert result["verdict"] == "Safe"


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
    assert result["reason"] == "ValidationError"
