from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem


class FormsAnalyzer:
    @property
    def name(self) -> str:
        return "forms"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        soup = BeautifulSoup(context.html or "", "html.parser")
        forms = []
        suspicious_count = 0
        base_url = context.final_url or context.normalized_url or context.submitted_url
        base_host = urlparse(base_url).hostname

        for index, form in enumerate(soup.find_all("form"), start=1):
            action_raw = str(form.get("action") or "").strip()
            action_url = urljoin(base_url, action_raw) if action_raw else base_url
            parsed_action = urlparse(action_url)
            input_types = [
                str(input_tag.get("type") or "text").lower()
                for input_tag in form.find_all(["input", "textarea", "select"])
            ]
            has_password = "password" in input_types
            has_sensitive_inputs = any(
                input_type in {"password", "email", "tel", "number"}
                for input_type in input_types
            )
            is_insecure_action = parsed_action.scheme == "http"
            is_external_action = bool(
                base_host and parsed_action.hostname and parsed_action.hostname != base_host
            )
            is_suspicious = has_password or is_insecure_action or is_external_action
            suspicious_count += 1 if is_suspicious else 0

            forms.append(
                {
                    "index": index,
                    "method": str(form.get("method") or "get").lower(),
                    "action": action_url,
                    "input_count": len(input_types),
                    "input_types": sorted(set(input_types)),
                    "has_password": has_password,
                    "has_sensitive_inputs": has_sensitive_inputs,
                    "is_insecure_action": is_insecure_action,
                    "is_external_action": is_external_action,
                }
            )

        severity = EvidenceSeverity.INFO
        if suspicious_count:
            has_password_form = any(form["has_password"] for form in forms)
            severity = EvidenceSeverity.HIGH if has_password_form else EvidenceSeverity.MEDIUM

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title=f"{len(forms)} form(s) discovered",
                description=(
                    "Forms were inspected for credential fields, insecure actions, and "
                    "external submission targets."
                ),
                data={
                    "form_count": len(forms),
                    "suspicious_form_count": suspicious_count,
                    "forms": forms,
                },
            )
        ]
