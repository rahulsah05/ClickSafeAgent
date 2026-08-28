from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from clicksafe.domain.evidence import EvidenceItem


class ToolSelection(BaseModel):
    tool: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=400)

    model_config = ConfigDict(extra="forbid")


class AgentDecision(BaseModel):
    reasoning_summary: str = Field(min_length=1, max_length=700)
    selected_tools: list[ToolSelection] = Field(default_factory=list, max_length=8)
    investigation_complete: bool
    risk_indicators: list[str] = Field(default_factory=list, max_length=12)
    unresolved_questions: list[str] = Field(default_factory=list, max_length=8)

    model_config = ConfigDict(extra="forbid")


AGENT_DECISION_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "reasoning_summary",
        "selected_tools",
        "investigation_complete",
        "risk_indicators",
        "unresolved_questions",
    ],
    "properties": {
        "reasoning_summary": {"type": "string"},
        "selected_tools": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["tool", "reason"],
                "properties": {
                    "tool": {"type": "string"},
                    "reason": {"type": "string"},
                },
            },
        },
        "investigation_complete": {"type": "boolean"},
        "risk_indicators": {
            "type": "array",
            "maxItems": 12,
            "items": {"type": "string"},
        },
        "unresolved_questions": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string"},
        },
    },
}


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    available: bool = True


@dataclass(frozen=True, slots=True)
class ToolExecutionOutcome:
    tool_name: str
    status: str
    summary: str
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class AgentStep:
    number: int
    planner_source: str
    reasoning_summary: str
    selected_tools: list[ToolSelection]
    tool_outcomes: list[ToolExecutionOutcome]
    risk_indicators: list[str]
    unresolved_questions: list[str]
    investigation_complete: bool

    def to_evidence(self) -> dict[str, Any]:
        return {
            "step": self.number,
            "planner_source": self.planner_source,
            "reasoning_summary": self.reasoning_summary,
            "selected_tools": [selection.model_dump() for selection in self.selected_tools],
            "tools_executed": [
                {
                    "tool": outcome.tool_name,
                    "status": outcome.status,
                    "summary": outcome.summary,
                    "error_code": outcome.error_code,
                }
                for outcome in self.tool_outcomes
            ],
            "risk_indicators": self.risk_indicators,
            "unresolved_questions": self.unresolved_questions,
            "investigation_complete": self.investigation_complete,
        }
