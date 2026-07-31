from enum import StrEnum


class Verdict(StrEnum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"


class AnalysisStatus(StrEnum):
    REQUESTED = "requested"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class EvidenceSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
