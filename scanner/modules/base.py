from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    fix_url: str = "/guide/"
    detail: Optional[str] = None

    def to_dict(self) -> dict:
        from scanner.score import SEVERITY_PENALTY
        d = asdict(self)
        d["severity"] = self.severity.value
        d["penalty"] = SEVERITY_PENALTY[self.severity]
        return d


class BaseScanModule(ABC):
    name: str = ""
    step_label: str = ""

    @abstractmethod
    def run(self, url: str, response=None) -> list[Finding]:
        ...
