from __future__ import annotations

from abc import ABC, abstractmethod

from core.context import AnalysisContext
from core.finding import Finding, RuleMetadata


class Rule(ABC):
    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata: ...

    @abstractmethod
    def run(self, context: AnalysisContext) -> list[Finding]: ...
