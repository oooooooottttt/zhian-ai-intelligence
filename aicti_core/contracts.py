"""Shared, serializable domain contracts. Integration chat owns this file."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

METHOD_VERSION = "core-v2"


@dataclass(frozen=True)
class Evidence:
    id: str
    observation_id: int
    revision_number: int
    source_id: str
    upstream_id: str
    kind: str
    title: str
    summary: str
    url: str
    aliases: tuple[str, ...] = ()
    components: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    withdrawn: bool = False
    collected_at: str = ""
    updated_at: str | None = None
    published_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Fact:
    predicate: str
    value: dict[str, Any]
    evidence_ids: tuple[str, ...]
    status: str = "valid"
    method: str = METHOD_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Assessment:
    asset_id: str
    version_match: str
    status: str
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    missing_conditions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EnrichmentResult:
    facts: tuple[Fact, ...] = ()
    assessments: tuple[Assessment, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
