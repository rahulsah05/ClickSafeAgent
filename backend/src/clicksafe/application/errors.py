class ClickSafeError(Exception):
    """Base error for expected application failures."""


class UrlValidationError(ClickSafeError):
    """Raised when a URL cannot be safely normalized for analysis."""


class UnsafeDestinationError(UrlValidationError):
    """Raised when a URL resolves to a destination that ClickSafe must not access."""


class AgentPlannerUnavailableError(ClickSafeError):
    """Raised when the AI planner cannot return a validated investigation decision."""


class AnalysisNotFoundError(ClickSafeError):
    """Raised when an analysis job cannot be found."""
