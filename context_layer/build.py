"""Runnable pipeline: rebuild the context layer and write the answers and issues.

    python3 -m context_layer.build            # writes context_layer/../out
    python3 -m context_layer.build --check    # rebuild twice, compare bytes

A rebuild replaces the model in memory from scratch; the same inputs always
produce the same entity ids, the same edges and byte-identical output.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .answers import answer_application_context, answer_terraform_management
from .ingest import load_inputs, load_manifest
from .model import format_timestamp
from .resolve import Resolver
from .store import ContextGraph, QueryScope

EXERCISE_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class BuildResult:
    graph: ContextGraph
    issues: list[dict[str, Any]]
    answers: dict[str, Any]
    as_of: datetime


def build(
    root: Path,
    tenant_id: str | None = None,
    environment: str | None = None,
    application_name: str | None = None,
) -> BuildResult:
    manifest = load_manifest(root)
    inputs = load_inputs(root, manifest)
    resolved = Resolver(inputs).run()
    graph = resolved.graph
    as_of = inputs.as_of
    defaults = dict(manifest.query_defaults)
    defaults.update(
        {key: value for key, value in (
            ("tenant_id", tenant_id),
            ("environment", environment),
            ("application_name", application_name),
        ) if value is not None}
    )
    effective_tenant = defaults["tenant_id"]
    if effective_tenant not in manifest.tenants:
        raise ValueError(
            f"tenant {effective_tenant!r} is not declared in the manifest; "
            f"known tenants: {', '.join(sorted(manifest.tenants))}"
        )
    scope = QueryScope(
        effective_tenant,
        defaults["environment"],
        "manifest query_defaults"
        + ("" if not (tenant_id or environment or application_name) else " (overridden)"),
    )
    answers = {
        "A": answer_terraform_management(graph, scope, as_of, defaults["environment"]),
        "B": answer_application_context(graph, scope, as_of, defaults["application_name"]),
    }
    return BuildResult(graph, [issue.to_dict() for issue in resolved.issues], answers, as_of)


def issues_document(
    graph: ContextGraph, issues: list[dict[str, Any]], as_of: datetime
) -> dict[str, Any]:
    ordered = sorted(
        issues, key=lambda issue: (issue["category"], issue["subject"], issue["summary"])
    )
    for number, issue in enumerate(ordered, start=1):
        issue["issue_id"] = f"ISS-{number:03d}"

    collection_rows = []
    for snapshot_id in sorted(graph.collections):
        collection = graph.collections[snapshot_id]
        collection_rows.append(
            {
                "snapshot_id": snapshot_id,
                "source_family": collection.source_family.value,
                "tenant_id": collection.tenant_id,
                "environment": collection.environment,
                "status": collection.status,
                "coverage": collection.coverage,
                "observed_at": format_timestamp(collection.observed_at),
                "age_seconds": collection.age_seconds(as_of),
                "freshness_budget_seconds": collection.freshness_budget_seconds,
                "freshness": collection.freshness(as_of),
                "scope": collection.scope,
            }
        )

    return {
        "title": "Issues report: unresolved links, conflicting observations, freshness and coverage",
        "evaluation_time": as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope_covered": "every tenant and environment in the supplied manifest; per-question "
        "limitations are additionally repeated inside each answer",
        "reading_guide": {
            "not_found_in_supplied_scope": "a collection declared complete for this scope did "
            "not report the thing; the claim is bounded by that scope and observation time",
            "unavailable / scope_unavailable": "no collection covered the scope; no claim in "
            "either direction is supported",
            "ambiguous": "candidates exist but the evidence does not say which one applies",
        },
        "counts_by_category": _counts(ordered),
        "issues": ordered,
        "collection_freshness": collection_rows,
    }


def _counts(issues: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for issue in issues:
        counts[issue["category"]] = counts.get(issue["category"], 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def dump(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def documents(result: BuildResult) -> dict[str, Any]:
    graph, as_of = result.graph, result.as_of
    return {
        "answer_a_terraform_management.json": result.answers["A"],
        "answer_b_application_context.json": result.answers["B"],
        "issues_report.json": issues_document(graph, result.issues, as_of),
        "model_summary.json": {
            "evaluation_time": as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "counts": graph.summary(),
            "identity_keys": {
                "cloud_instance": "tenant + account_id + region + InstanceId",
                "cloud_database": "tenant + DBInstanceArn",
                "terraform_resource": "tenant + workspace_id + address",
                "kubernetes_object": "tenant + cluster_id + kind + namespace + name",
                "kubernetes_incarnation": "tenant + cluster_id + metadata.uid",
                "catalog_application": "tenant + service_id + declared environment",
            },
        },
    }


def write_outputs(out_dir: Path, result: BuildResult) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, payload in sorted(documents(result).items()):
        path = out_dir / name
        path.write_text(dump(payload), encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=EXERCISE_ROOT)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--tenant", default=None, help="override the manifest query default")
    parser.add_argument("--environment", default=None, help="override the manifest query default")
    parser.add_argument("--application", default=None, help="override the manifest query default")
    parser.add_argument("--stdout", action="store_true", help="print instead of writing files")
    parser.add_argument("--check", action="store_true", help="rebuild twice and compare output")
    args = parser.parse_args(argv)
    root = args.root.resolve()

    overrides = (args.tenant, args.environment, args.application)
    try:
        result = build(root, *overrides)
    except ValueError as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 2

    if args.stdout or (any(overrides) and args.out is None):
        for name, payload in sorted(documents(result).items()):
            print(f"===== {name}")
            print(dump(payload), end="")
        return 0

    out_dir = args.out or root / "out"
    written = write_outputs(out_dir, result)

    if args.check:
        rebuilt = build(root, *overrides)
        if dump(documents(result)) != dump(documents(rebuilt)):
            print(
                "Rebuild produced different output; the pipeline is not deterministic.",
                file=sys.stderr,
            )
            return 1
        print("Deterministic rebuild check passed: identical output from the same inputs.")

    for path in written:
        print(f"wrote {path.relative_to(root)}")
    graph = result.graph
    print(
        f"entities: {len(graph.entities)} edges: {len(graph.edges)} "
        f"unresolved: {len(graph.unresolved)} conflicts: {len(graph.conflicts)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
