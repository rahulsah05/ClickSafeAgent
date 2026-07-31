import re

from bs4 import BeautifulSoup

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem

SUSPICIOUS_PATTERNS = {
    "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "document_write": re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE),
    "base64_decode": re.compile(r"\batob\s*\(", re.IGNORECASE),
    "unescape": re.compile(r"\bunescape\s*\(", re.IGNORECASE),
    "location_replace": re.compile(r"\blocation\.(replace|href)\b", re.IGNORECASE),
    "credential_keyword": re.compile(r"(password|passwd|credential|login)", re.IGNORECASE),
}


class JavaScriptAnalyzer:
    @property
    def name(self) -> str:
        return "javascript"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        soup = BeautifulSoup(context.html or "", "html.parser")
        scripts = soup.find_all("script")
        inline_script_text = "\n".join(
            script.string or "" for script in scripts if not script.get("src")
        )
        external_scripts = [str(script.get("src")) for script in scripts if script.get("src")]
        event_handler_count = sum(
            1
            for tag in soup.find_all(True)
            for attribute in tag.attrs
            if str(attribute).lower().startswith("on")
        )

        matched_patterns = [
            name
            for name, pattern in SUSPICIOUS_PATTERNS.items()
            if pattern.search(inline_script_text)
        ]
        severity = EvidenceSeverity.INFO
        if matched_patterns or event_handler_count > 20:
            severity = EvidenceSeverity.MEDIUM
        if {"eval", "base64_decode"}.issubset(set(matched_patterns)):
            severity = EvidenceSeverity.HIGH

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title="JavaScript surface inspected",
                description=(
                    "Inline and external scripts were inspected for simple suspicious "
                    "patterns."
                ),
                data={
                    "script_count": len(scripts),
                    "external_script_count": len(external_scripts),
                    "inline_script_count": len(scripts) - len(external_scripts),
                    "event_handler_count": event_handler_count,
                    "matched_patterns": matched_patterns,
                    "external_scripts_sample": external_scripts[:20],
                },
            )
        ]
