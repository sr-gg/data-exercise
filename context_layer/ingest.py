"""Read the supplied extracts into collection-tagged raw records.

A record's tenant, environment, account, region, cluster or workspace is taken
from the *manifest entry for the collection that supplied it*, never from the
file it happens to live in: ``aws_inventory.json`` and ``k8s_resources.json``
each carry several tenants and environments, and ``service_catalog.csv`` carries
two collections in one file.

Record-reference format (the output contract's "source file plus record
identifier"): ``<payload_path>#<locator>``, where the locator is a JSON pointer
for JSON payloads and a 1-based physical line number for CSV rows.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .model import Collection, SourceFamily, parse_timestamp


def record_ref(payload_path: str, pointer: str) -> str:
    return f"{payload_path}#{pointer}"


@dataclass(frozen=True)
class Manifest:
    as_of: datetime
    tenants: tuple[str, ...]
    query_defaults: dict[str, Any]
    collections: dict[str, Collection]


@dataclass(frozen=True)
class RawRecord:
    collection: Collection
    record_ref: str
    data: dict[str, Any]
    parent: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


@dataclass
class LoadedInputs:
    manifest: Manifest
    root: Path
    aws_instances: list[RawRecord] = field(default_factory=list)
    aws_databases: list[RawRecord] = field(default_factory=list)
    terraform_resources: list[RawRecord] = field(default_factory=list)
    k8s_objects: list[RawRecord] = field(default_factory=list)
    catalog_rows: list[RawRecord] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def as_of(self) -> datetime:
        return self.manifest.as_of


def load_manifest(root: Path) -> Manifest:
    raw = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    collections: dict[str, Collection] = {}
    for entry in raw["snapshots"]:
        snapshot_id = entry["snapshot_id"]
        if snapshot_id in collections:
            raise ValueError(f"duplicate snapshot_id {snapshot_id}")
        collections[snapshot_id] = Collection(
            snapshot_id=snapshot_id,
            source_family=SourceFamily(entry["source_family"]),
            source_instance_id=entry["source_instance_id"],
            tenant_id=entry["tenant_id"],
            payload_path=entry["payload_path"],
            observed_at=parse_timestamp(entry["observed_at"]),
            exported_at=parse_timestamp(entry["exported_at"]),
            freshness_budget_seconds=entry["freshness_budget_seconds"],
            status=entry["status"],
            coverage=entry["coverage"],
            scope=dict(entry["scope"]),
        )
    return Manifest(
        as_of=parse_timestamp(raw["as_of"]),
        tenants=tuple(raw["tenants"]),
        query_defaults=dict(raw["query_defaults"]),
        collections=collections,
    )


def _read_json(root: Path, relative: str) -> Any:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"payload path escapes repository root: {relative}")
    return json.loads(path.read_text(encoding="utf-8"))


def _group_by_snapshot(manifest: Manifest, payload: Any, family: SourceFamily) -> list[RawRecord]:
    """Match each payload group to its manifest entry by snapshot_id."""
    records: list[RawRecord] = []
    if family is SourceFamily.TERRAFORM:
        collection = manifest.collections[payload["snapshot_id"]]
        parent = {
            "lineage": payload.get("lineage"),
            "serial": payload.get("serial"),
            "workspace_id": collection.scope.get("workspace_id"),
            "payload_path": collection.payload_path,
        }
        for index, resource in enumerate(payload["resources"]):
            records.append(
                RawRecord(
                    collection=collection,
                    record_ref=record_ref(
                        collection.payload_path, f"/resources/{index}"
                    ),
                    data=resource,
                    parent=parent,
                )
            )
        return records

    for group in payload["collections"]:
        collection = manifest.collections[group["snapshot_id"]]
        base = f"/collections/{group['snapshot_id']}"
        for key, bucket in (("instances", "aws_instances"), ("databases", "aws_databases")):
            for index, item in enumerate(group.get(key, [])):
                pointer = f"{base}/{key}/{index}"
                records.append(
                    RawRecord(
                        collection=collection,
                        record_ref=record_ref(collection.payload_path, pointer),
                        data=item,
                        parent={"bucket": bucket},
                    )
                )
    return records


def _load_catalog(root: Path, manifest: Manifest, relative: str) -> list[RawRecord]:
    records: list[RawRecord] = []
    with (root / relative).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        for line_number, row in enumerate(reader, start=2):
            snapshot_id = row["snapshot_id"]
            collection = manifest.collections[snapshot_id]
            records.append(
                RawRecord(
                    collection=collection,
                    record_ref=record_ref(relative, f"line={line_number}"),
                    data={key: (value or None) for key, value in row.items()},
                )
            )
    return records


def load_inputs(root: Path, manifest: Manifest | None = None) -> LoadedInputs:
    root = Path(root)
    manifest = manifest or load_manifest(root)
    loaded = LoadedInputs(manifest=manifest, root=root)

    seen_files: set[tuple[str, str]] = set()
    for collection in sorted(manifest.collections.values(), key=lambda c: c.snapshot_id):
        if not collection.available:
            continue
        family = collection.source_family
        file_key = (family.value, str(collection.payload_path))
        if file_key in seen_files:
            continue
        seen_files.add(file_key)
        payload_path = str(collection.payload_path)
        if family in (SourceFamily.AWS, SourceFamily.KUBERNETES, SourceFamily.TERRAFORM):
            payload = _read_json(root, payload_path)
            if family is SourceFamily.KUBERNETES:
                for group in payload["collections"]:
                    group_collection = manifest.collections[group["snapshot_id"]]
                    base = f"/collections/{group['snapshot_id']}"
                    for index, item in enumerate(group["items"]):
                        loaded.k8s_objects.append(
                            RawRecord(
                                collection=group_collection,
                                record_ref=record_ref(
                                    group_collection.payload_path, f"{base}/items/{index}"
                                ),
                                data=item,
                            )
                        )
                continue
            for record in _group_by_snapshot(manifest, payload, family):
                if family is SourceFamily.TERRAFORM:
                    loaded.terraform_resources.append(record)
                elif record.parent["bucket"] == "aws_instances":
                    loaded.aws_instances.append(record)
                else:
                    loaded.aws_databases.append(record)
        elif family is SourceFamily.CATALOG:
            loaded.catalog_rows.extend(_load_catalog(root, manifest, payload_path))

    declared = {record.collection.snapshot_id for record in _all(loaded)}
    for snapshot_id, collection in manifest.collections.items():
        if collection.available and snapshot_id not in declared:
            loaded.problems.append(
                f"{snapshot_id}: manifest declares a payload but no records were grouped"
            )
    return loaded


def _all(loaded: LoadedInputs) -> list[RawRecord]:
    return (
        loaded.aws_instances
        + loaded.aws_databases
        + loaded.terraform_resources
        + loaded.k8s_objects
        + loaded.catalog_rows
    )


def tag_mapping(tags: list[dict[str, str]] | None) -> dict[str, str]:
    """Normalise the AWS tag array. An omitted tag is not an empty-string claim."""
    if not tags:
        return {}
    return {entry["Key"]: entry["Value"] for entry in tags}
