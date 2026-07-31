from dataclasses import asdict

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem


class RedirectAnalyzer:
    @property
    def name(self) -> str:
        return "redirects"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        redirects = context.metadata.get("browser_redirects", [])
        redirect_count = len(redirects)
        final_url = context.final_url
        normalized_url = context.normalized_url

        severity = EvidenceSeverity.INFO
        title = "No redirects observed"
        description = "The browser did not observe HTTP redirect responses."
        if redirect_count > 0:
            severity = EvidenceSeverity.LOW if redirect_count <= 2 else EvidenceSeverity.MEDIUM
            title = f"{redirect_count} redirect response(s) observed"
            description = "The page changed destination through HTTP redirects before loading."

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title=title,
                description=description,
                data={
                    "submitted_url": context.submitted_url,
                    "normalized_url": normalized_url,
                    "final_url": final_url,
                    "final_url_changed": bool(
                        final_url and normalized_url and final_url != normalized_url
                    ),
                    "redirect_count": redirect_count,
                    "redirects": [
                        asdict(redirect) if hasattr(redirect, "__dataclass_fields__") else redirect
                        for redirect in redirects
                    ],
                },
            )
        ]
