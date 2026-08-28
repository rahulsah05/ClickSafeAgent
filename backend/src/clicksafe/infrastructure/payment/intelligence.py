from typing import Any, Protocol


class PaymentIntelligenceClient(Protocol):
    """Optional adapter for a legitimate wallet or payment reputation provider."""

    async def lookup_destination(
        self,
        *,
        destination_type: str,
        destination: str,
    ) -> dict[str, Any]:
        ...
