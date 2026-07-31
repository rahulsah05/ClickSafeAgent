from bs4 import BeautifulSoup

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem


class HtmlAnalyzer:
    @property
    def name(self) -> str:
        return "html"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        html = context.html or ""
        soup = BeautifulSoup(html, "html.parser")
        anchors = soup.find_all("a")
        images = soup.find_all("img")
        iframes = soup.find_all("iframe")
        hidden_inputs = soup.find_all("input", attrs={"type": "hidden"})
        body_text = soup.get_text(" ", strip=True)

        severity = EvidenceSeverity.INFO
        suspicious_markers = []
        if len(hidden_inputs) > 20:
            suspicious_markers.append("many_hidden_inputs")
        if iframes:
            suspicious_markers.append("iframes_present")
        if len(body_text) < 80 and (anchors or images):
            suspicious_markers.append("thin_content")
        if suspicious_markers:
            severity = EvidenceSeverity.LOW

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title="HTML structure inspected",
                description="Captured HTML was summarized for structural phishing indicators.",
                data={
                    "html_available": bool(html),
                    "html_characters": len(html),
                    "text_characters": len(body_text),
                    "anchor_count": len(anchors),
                    "image_count": len(images),
                    "iframe_count": len(iframes),
                    "hidden_input_count": len(hidden_inputs),
                    "suspicious_markers": suspicious_markers,
                },
            )
        ]
