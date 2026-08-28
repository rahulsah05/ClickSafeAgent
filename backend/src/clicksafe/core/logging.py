import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from clicksafe.core.request_context import get_request_id


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None) or get_request_id()
        if request_id is not None:
            payload["request_id"] = request_id

        for field_name in (
            "event",
            "analysis_id",
            "http_method",
            "http_path",
            "http_status_code",
            "duration_ms",
        ):
            value = getattr(record, field_name, None)
            if value is not None:
                payload[field_name] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True, default=str)


def configure_logging(log_level: str) -> None:
    application_logger = logging.getLogger("clicksafe")
    if application_logger.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    application_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    application_logger.addHandler(handler)
    application_logger.propagate = False
