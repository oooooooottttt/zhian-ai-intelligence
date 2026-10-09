from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceConfig:
    id: str
    name: str
    adapter: str
    category: str
    endpoint: str
    allowed_hosts: tuple[str, ...]
    interval_seconds: int = 3600
    min_request_interval_seconds: float = 3.0
    enabled: bool = True
    terms_url: str = ""
    content_scope: str = "metadata_only"
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Record:
    source_id: str
    upstream_id: str
    kind: str
    title: str
    summary: str
    url: str
    published_at: str | None = None
    updated_at: str | None = None
    aliases: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FetchResult:
    records: list[Record]
    cursor: dict[str, Any]
    complete: bool = True
    not_modified: bool = False


@dataclass
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    url: str

    def json(self) -> Any:
        return json.loads(self.body)

    def text(self) -> str:
        return self.body.decode("utf-8-sig", errors="replace")


class FetchError(Exception):
    def __init__(self, message: str, status: int | None = None,
                 retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class FetchBudgetExceeded(FetchError):
    pass
