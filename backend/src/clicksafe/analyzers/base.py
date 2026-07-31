from typing import Protocol

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.evidence import EvidenceItem


class Analyzer(Protocol):
    @property
    def name(self) -> str:
        ...

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        ...
