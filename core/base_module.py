import abc
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List

@dataclass
class ModuleResult:
    module_name: str
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "UNKNOWN"
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class BaseModule(abc.ABC):
    def __init__(self, target: str, config: Dict[str, Any] = None):
        self.target = target
        self.config = config or {}

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique identifier for the module."""
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Brief summary of the module's function."""
        pass

    @abc.abstractmethod
    def run(self) -> ModuleResult:
        """Executes the module logic and returns a ModuleResult."""
        pass

    def http_client(self, **overrides):
        """Build a scoped, audited, cached HttpClient for this module.

        Scope/audit/cache_dir come from the engine via config keys
        (_scope, _audit, _cache_dir, _allow_all). Fail-closed: without a
        scope (and without _allow_all) this raises ValueError before any
        socket opens.
        """
        from core.http import HttpClient
        kw = dict(tool=self.name,
                  scope=self.config.get("_scope"),
                  audit=self.config.get("_audit"),
                  cache_dir=self.config.get("_cache_dir"),
                  allow_all=self.config.get("_allow_all", False))
        kw.update(overrides)
        return HttpClient(**kw)
