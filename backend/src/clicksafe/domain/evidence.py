from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from clicksafe.domain.enums import EvidenceSeverity


class EvidenceCategory(StrEnum):
    TECHNICAL = "technical"
    REPUTATION = "reputation"
    BROWSER = "browser"
    VALIDATION = "validation"


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    source: str
    severity: EvidenceSeverity
    title: str
    description: str
    category: EvidenceCategory = EvidenceCategory.TECHNICAL
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    items: list[EvidenceItem]

    def by_source(self) -> dict[str, list[EvidenceItem]]:
        grouped: dict[str, list[EvidenceItem]] = {}
        for item in self.items:
            grouped.setdefault(item.source, []).append(item)
        return grouped
