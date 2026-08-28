import re
from typing import Any, Protocol
from urllib.parse import urlparse

from clicksafe.application.agent.agent_models import AgentDecision, ToolSelection


class AgentPlanner(Protocol):
    async def decide(self, investigation: dict[str, Any]) -> AgentDecision:
        ...


class HeuristicAgentPlanner:
    """Evidence-driven fallback planner used when the OpenAI planner is unavailable."""

    async def decide(self, investigation: dict[str, Any]) -> AgentDecision:
        available = {str(tool["name"]) for tool in investigation["available_tools"]}
        used = set(str(tool) for tool in investigation["tools_used"])
        browser = investigation["browser"]
        technical = investigation["technical_evidence"]
        reputation = investigation["reputation_evidence"]

        if not browser["captured"]:
            return self._decision(
                "Initial browser evidence is required before selecting content or domain tools.",
                [self._selection("browser_scan", "Capture the page, redirects, and safe initial clues.")],
                complete=False,
            )

        selections: list[ToolSelection] = []
        page_text = f"{browser.get('page_title') or ''} {browser.get('body_text_sample') or ''}".lower()
        final_url_changed = self._final_host_changed(
            investigation["normalized_url"],
            browser.get("final_url"),
        )
        redirect_count = int(browser.get("redirect_count") or 0)

        if "html_analysis" not in used:
            selections.append(
                self._selection("html_analysis", "Establish page structure and hidden-content signals.")
            )
        elif "metadata_analysis" not in used:
            selections.append(
                self._selection("metadata_analysis", "Inspect the page identity and canonical metadata.")
            )

        if redirect_count > 0 or final_url_changed:
            self._add_domain_investigation(
                selections,
                used,
                "Redirect or destination changes warrant domain and reputation checks.",
            )

        if re.search(r"\b(login|sign in|password|verify (?:your )?account|credential)\b", page_text):
            self._add_selection(
                selections,
                used,
                "form_analysis",
                "Visible login or verification language may indicate a credential flow.",
            )

        if re.search(
            r"\b(pay(?:ment)?|crypto|bitcoin|ethereum|wallet|wire transfer|bank transfer|gift card)\b",
            page_text,
        ):
            self._add_selection(
                selections,
                used,
                "payment_analysis",
                "Payment-related language warrants destination and wallet inspection.",
            )

        for item in technical:
            signals = item.get("signals", {})
            if item.get("source") == "html" and signals.get("suspicious_markers"):
                self._add_selection(
                    selections,
                    used,
                    "javascript_analysis",
                    "Structural indicators justify inspecting script behavior.",
                )
            if item.get("source") == "forms" and int(signals.get("suspicious_form_count") or 0) > 0:
                self._add_domain_investigation(
                    selections,
                    used,
                    "Suspicious form behavior warrants domain and reputation checks.",
                )
            if item.get("source") == "payment" and signals.get("suspicious_indicators"):
                self._add_domain_investigation(
                    selections,
                    used,
                    "Payment risk indicators warrant destination reputation checks.",
                )
            if item.get("source") == "javascript" and signals.get("matched_patterns"):
                self._add_domain_investigation(
                    selections,
                    used,
                    "Suspicious JavaScript warrants destination reputation checks.",
                )

        if not reputation and any(item.get("severity") in {"high", "critical"} for item in technical):
            self._add_domain_investigation(
                selections,
                used,
                "High-severity technical evidence warrants reputation confirmation.",
            )

        valid_selections = [selection for selection in selections if selection.tool in available]
        if not valid_selections:
            return self._decision(
                "Available evidence has been inspected sufficiently under the local fallback policy.",
                [],
                complete=True,
            )

        return self._decision(
            "Selected only the next tools justified by the current evidence.",
            valid_selections[:6],
            complete=False,
        )

    def _add_domain_investigation(
        self,
        selections: list[ToolSelection],
        used: set[str],
        reason: str,
    ) -> None:
        for tool in (
            "redirect_analysis",
            "dns_analysis",
            "ssl_analysis",
            "whois_analysis",
            "virustotal_lookup",
            "google_safe_browsing_lookup",
        ):
            self._add_selection(selections, used, tool, reason)

    def _add_selection(
        self,
        selections: list[ToolSelection],
        used: set[str],
        tool: str,
        reason: str,
    ) -> None:
        if tool not in used and all(selection.tool != tool for selection in selections):
            selections.append(self._selection(tool, reason))

    def _selection(self, tool: str, reason: str) -> ToolSelection:
        return ToolSelection(tool=tool, reason=reason)

    def _decision(
        self,
        summary: str,
        selections: list[ToolSelection],
        *,
        complete: bool,
    ) -> AgentDecision:
        return AgentDecision(
            reasoning_summary=summary,
            selected_tools=selections,
            investigation_complete=complete,
            risk_indicators=[],
            unresolved_questions=[],
        )

    def _final_host_changed(self, normalized_url: str, final_url: object) -> bool:
        if not isinstance(final_url, str):
            return False
        return urlparse(normalized_url).hostname != urlparse(final_url).hostname
