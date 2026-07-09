from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BreachSearchResult:
    success: bool
    indicator: str
    indicator_type: str
    breaches: list
    error: Optional[str] = None


class DarkWebProvider(ABC):

    @abstractmethod
    def search_breaches(
        self, indicator: str, indicator_type: Optional[str] = None
    ) -> BreachSearchResult:
        ...

    def detect_asset_type(self, asset: str) -> str:
        a = asset.strip()
        if not a:
            return "username"
        if "@" in a:
            return "email"
        clean = a.replace("+", "").replace("-", "").replace(" ", "").replace("(", "").replace(")", "")
        if a.startswith("+") or (clean.isdigit() and 8 <= len(clean) <= 15):
            return "phone"
        if "." in a and " " not in a:
            return "domain"
        return "username"
