from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod
from typing import Optional

from pages.constants import GUIDE_ANCHOR_PAGE


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
    doc_url: Optional[str] = None

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


def guide_url(anchor: str) -> str:
    """Sestavit URL na konkrétní kotvu v rozděleném /guide/.

    Anchor je vyhledán v GUIDE_ANCHOR_PAGE. Pokud chybí, default = 'prompts'
    (bezpečnější než 404 — anchor se prostě nepřescroluje).
    """
    page = GUIDE_ANCHOR_PAGE.get(anchor, "prompts")
    return f"/guide/{page}/#{anchor}"
