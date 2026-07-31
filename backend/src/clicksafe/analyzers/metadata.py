from bs4 import BeautifulSoup

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem


class MetadataAnalyzer:
    @property
    def name(self) -> str:
        return "metadata"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        soup = BeautifulSoup(context.html or "", "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        description = self._meta_content(soup, "description")
        canonical = self._canonical_href(soup)
        robots = self._meta_content(soup, "robots")
        generator = self._meta_content(soup, "generator")
        has_open_graph = (
            soup.find("meta", property=lambda value: value and value.startswith("og:"))
            is not None
        )

        missing_items = [
            label
            for label, value in {
                "title": title,
                "description": description,
                "canonical": canonical,
            }.items()
            if not value
        ]
        severity = EvidenceSeverity.INFO if len(missing_items) <= 1 else EvidenceSeverity.LOW

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title="Page metadata extracted",
                description="Basic document metadata was extracted from the captured HTML.",
                data={
                    "title": title,
                    "description": description,
                    "canonical": canonical,
                    "robots": robots,
                    "generator": generator,
                    "has_open_graph": has_open_graph,
                    "missing_items": missing_items,
                },
            )
        ]

    def _meta_content(self, soup: BeautifulSoup, name: str) -> str | None:
        tag = soup.find("meta", attrs={"name": name})
        content = tag.get("content") if tag else None
        return str(content).strip() if content else None

    def _canonical_href(self, soup: BeautifulSoup) -> str | None:
        tag = soup.find("link", rel=lambda value: value and "canonical" in value)
        href = tag.get("href") if tag else None
        return str(href).strip() if href else None
