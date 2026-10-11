"""Hardened module contract.

Anti-hallucination machinery (doctrine principles 13-20):
  - Finding: every finding carries claim -> tag -> method -> evidence ->
    observed_date -> confidence. Break the chain anywhere and it doesn't ship.
  - Claim tags: OBSERVED (directly seen, method+date named) | INFERRED
    (reasoned from observations, reasoning shown) | ASSUMED (working
    assumption, never briefed as fact). Untagged factual claim = fabrication.
  - Confidence: VERIFIED | CORROBORATED | DEBUNKED | STALE | UNVERIFIABLE |
    CONTESTED | LEAD. No label, no finding.
  - Single-source quarantine: quarantined=True caps the finding at LEAD.
  - Burn notice: burned=True retracts the finding but keeps the record.

Module contract (doctrine section 4): every module declares a plain-English
alias, what it reads, what it returns, and — mandatory — its failure modes.
A module description without its failure modes is incomplete.
"""
import abc
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List

# Doctrine: no label, no finding.
CONFIDENCES = ("VERIFIED", "CORROBORATED", "DEBUNKED", "STALE",
               "UNVERIFIABLE", "CONTESTED", "LEAD")

# Doctrine principle 13: untagged factual claim = fabrication.
TAGS = ("OBSERVED", "INFERRED", "ASSUMED")


@dataclass
class Finding:
    """One evidence-chained finding.

    Mandatory shape: claim -> tag -> method -> evidence -> observed_date
    -> confidence. Findings live alongside ModuleResult.data (never replace
    it), so existing consumers keep working while reports gain provenance.
    """
    claim: str
    tag: str = "OBSERVED"
    method: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    observed_date: str = ""
    confidence: str = "LEAD"
    quarantined: bool = False
    burned: bool = False
    module_name: str = ""
    target: str = ""

    def __post_init__(self):
        if self.tag not in TAGS:
            raise ValueError("bad claim tag %r; must be one of %s" % (self.tag, TAGS))
        if self.confidence not in CONFIDENCES:
            raise ValueError("bad confidence %r; must be one of %s"
                             % (self.confidence, CONFIDENCES))
        if self.quarantined and self.confidence not in ("LEAD", "DEBUNKED"):
            # Single-source quarantine caps at LEAD. No amount of detail
            # from one source equals two sources.
            raise ValueError("quarantined finding must be LEAD (or DEBUNKED)")
        if not self.observed_date:
            # Intelligence rots: everything is dated, even "now".
            self.observed_date = datetime.now(timezone.utc).date().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def burn(self, reason: str) -> None:
        """Burn notice (doctrine principle 18): retract the finding, keep
        the record. No quiet fixes."""
        self.burned = True
        self.confidence = "DEBUNKED"
        self.quarantined = False
        self.evidence = {"burn_notice": reason,
                         "burned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         "prior_evidence": self.evidence}


def gap_finding(module_name: str, target: str, what: str) -> Finding:
    """Doctrine principle 14: gaps stay gaps. Missing evidence produces
    exactly one output: UNKNOWN — not observed."""
    return Finding(
        claim="UNKNOWN — not observed: %s" % what,
        tag="OBSERVED",
        method="gap discipline: evidence absent, no fill attempted",
        evidence={},
        confidence="UNVERIFIABLE",
        module_name=module_name,
        target=target,
    )


@dataclass
class ModuleResult:
    module_name: str
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "UNKNOWN"
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() if isinstance(f, Finding) else f
                         for f in self.findings]
        return d

    def add_finding(self, claim: str, tag: str = "OBSERVED", method: str = "",
                    evidence: Dict[str, Any] = None, confidence: str = "LEAD",
                    quarantined: bool = False) -> Finding:
        """Convenience: build, validate, and attach a Finding in one call."""
        f = Finding(claim=claim, tag=tag, method=method,
                    evidence=evidence or {}, confidence=confidence,
                    quarantined=quarantined,
                    module_name=self.module_name, target=self.target)
        self.findings.append(f)
        return f


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

    # -- Hardened contract (concrete defaults so existing modules keep
    #    loading; validate_contract() enforces completeness) -------------

    @property
    def alias(self) -> str:
        """Plain-English alias. The operator tasks in plain language and the
        module translates to tradecraft, never the reverse."""
        return ""

    @property
    def reads(self) -> str:
        """What this module reads (sources)."""
        return ""

    @property
    def returns(self) -> str:
        """What this module returns."""
        return ""

    @property
    def failure_modes(self) -> List[str]:
        """How this module's output can be wrong. Mandatory — a module
        description without its failure modes is incomplete."""
        return []

    @property
    def requires_auth(self) -> bool:
        """True when the module goes beyond ordinary public browsing and
        needs explicit per-action authorization under the ROE
        (doctrine section 6)."""
        return False

    def validate_contract(self) -> List[str]:
        """Returns a list of contract problems; empty means complete."""
        problems = []
        if not self.alias:
            problems.append("missing plain-English alias")
        if not self.reads:
            problems.append("missing 'reads' declaration")
        if not self.returns:
            problems.append("missing 'returns' declaration")
        if not self.failure_modes:
            problems.append("missing failure modes (mandatory)")
        return problems

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

    def scoped_client(self):
        """http_client() that fails soft: returns (client, error). Use when
        a module must report misconfiguration as FAILED instead of raising."""
        try:
            return self.http_client(), None
        except ValueError as e:
            return None, str(e)
