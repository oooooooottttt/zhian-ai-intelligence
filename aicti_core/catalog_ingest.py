"""Explicit curated official metadata imports, isolated from fictional demos."""
from __future__ import annotations

from dataclasses import replace
from urllib.parse import urlsplit

from .store import utc_now

CATALOG_SOURCES = ("catalog-nist", "catalog-eurlex")


def seed_catalog(monitor_store):
    from .knowledge_catalog import catalog_records
    groups = {}
    for record in catalog_records():
        host = urlsplit(record.url).hostname
        source = "catalog-nist" if host in {"www.nist.gov","csrc.nist.gov"} else "catalog-eurlex" if host=="eur-lex.europa.eu" else None
        if source is None or record.metadata.get("monitoring")!="curated":
            continue
        record = replace(record,source_id=source,metadata={**record.metadata,
            "curated":True,"source_category":record.metadata["knowledge_kind"]})
        groups.setdefault(source,[]).append(record)
    for source,records in groups.items():
        at = utc_now()
        run = monitor_store.begin_run(source,at)
        monitor_store.ingest_and_finish(run,source,records,{"curated_catalog":"2026-10-04"},at,at,True,
            preserve_restrictions=True)
    return {"sources":len(groups),"items":sum(map(len,groups.values()))}
