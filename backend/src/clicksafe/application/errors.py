class ClickSafeError(Exception):
    """Base error for expected application failures."""


class UrlValidationError(ClickSafeError):
    """Raised when a URL cannot be safely normalized for analysis."""


class AnalysisNotFoundError(ClickSafeError):
    """Raised when an analysis job cannot be found."""

