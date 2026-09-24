"""The two required questions, answered by querying the resolved graph.

Nothing here re-derives identity or matches records: results come from traversing
edges the resolver created, and limitations come from the unresolved links and
conflicts stored alongside them. Every evidence record emitted is checked against
the caller's tenant scope before it reaches the output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .model import (
    Collection,
    Edge,
    EdgeKind,
    Entity,
    EntityKind,
    EvidenceStatus,
    SourceFamily,
)
from .resolve import terraform_scope_covers
from .store import ContextGraph, QueryScope

PROVIDER_ID_NOTE = (
    "A managed-binding record in the supplied Terraform state establishes only that the "
    "state, at its observation time, held a managed resource for that provider ARN. It does "
    "not establish that the resource is currently managed, that the workspace still exists, "
    "or that no other workspace manages it."
)


def _evidence_dicts(graph: ContextGraph, scope: QueryScope, items) -> list[dict[str, Any]]:
    return [
        evidence.to_dict()
        for evidence in sorted(
            graph.check_evidence(scope, items),
            key=lambda e: (e.record_ref, e.snapshot_id),
        )
    ]


def _collection_note(collection: Collection, as_of: datetime) -> str:
    return collection.describe_freshness(as_of)


def answer_terraform_management(
    graph: ContextGraph,
    scope: QueryScope,
    as_of: datetime,
    environment: str,
) -> dict[str, Any]:
    """Question A: running production instances and their managed-binding evidence."""
    population = [
        entity
        for entity in graph.entities_in(scope, [EntityKind.CLOUD_INSTANCE])
        if entity.attributes.get("state_name") == "running"
    ]
    tf_state, tf_collections = terraform_scope_covers(
        graph, scope, as_of, environment, "aws_instance"
    )
    stale_collections = [
        collection
        for collection in graph.collections_in(scope, SourceFamily.TERRAFORM.value)
        if collection.freshness(as_of) == "stale"
    ]

    results: list[dict[str, Any]] = []
    counterfactuals: list[dict[str, Any]] = []
    tally = {status.value: 0 for status in EvidenceStatus}

    for entity in population:
        managed = graph.edges_to(scope, entity.entity_id, [EdgeKind.MANAGED_BINDING])
        data_only = graph.edges_to(scope, entity.entity_id, [EdgeKind.DATA_REFERENCE])
        entry: dict[str, Any] = {
            "entity_id": entity.entity_id,
            "instance_id": entity.attributes["instance_id"],
            "display_name": entity.attributes.get("display_name"),
            "observed_state": entity.attributes.get("state_name"),
            "environment_classification": {
                "value": environment,
                "why": "the manifest collection scope is authoritative for environment; the "
                "source Environment tag is reported separately as a source statement",
                "source_environment_tag": entity.attributes.get("source_environment_tag"),
            },
            "inventory_evidence": _evidence_dicts(graph, scope, entity.evidence),
        }
        if managed:
            verdict: dict[str, Any] = {
                "status": EvidenceStatus.FOUND.value,
                "bindings": [_binding_dict(graph, scope, edge) for edge in managed],
            }
        elif tf_state == "unavailable":
            verdict = {
                "status": EvidenceStatus.UNAVAILABLE.value,
                "why": "no Terraform collection was supplied for this tenant and environment, "
                "so neither presence nor absence of a binding can be established",
            }
        elif data_only:
            verdict = {
                "status": EvidenceStatus.NOT_FOUND_IN_SUPPLIED_SCOPE.value,
                "why": "the only Terraform record naming this ARN has mode=data, which is a "
                "data-source reference: it reads an existing object and is not a "
                "managed-resource binding",
                "data_references": [_binding_dict(graph, scope, edge) for edge in data_only],
            }
        else:
            verdict = {
                "status": EvidenceStatus.NOT_FOUND_IN_SUPPLIED_SCOPE.value,
                "why": "no managed resource in the supplied Terraform state references this "
                "instance ARN" + _scope_qualifier(tf_state, tf_collections),
            }
        tally[verdict["status"]] += 1
        entry["managed_binding"] = verdict
        results.append(entry)

    for link in sorted(graph.unresolved, key=lambda link: (link.from_id, link.target)):
        if link.tenant_id != scope.tenant_id or link.environment != environment:
            continue
        if link.kind not in (EdgeKind.MANAGED_BINDING, EdgeKind.DATA_REFERENCE):
            continue
        source = graph.entities.get(link.from_id)
        if source is None or source.kind is not EntityKind.TERRAFORM_RESOURCE:
            continue
        counterfactuals.append(
            {
                "entity_id": link.from_id,
                "terraform_address": source.attributes["address"],
                "mode": source.attributes["mode"],
                "referenced_arn": link.target,
                "state_observed_at": source.evidence[-1].observed_at,
                "link_state": link.state.value,
                "reason": link.reason,
                "resolving_evidence": link.resolving_evidence,
                "evidence": _evidence_dicts(graph, scope, link.evidence),
            }
        )

    limitations = [
        PROVIDER_ID_NOTE,
        "The population is bounded by the supplied inventory: this is every instance the "
        "cloud collections reported as running for this tenant and environment, not a claim "
        "about instances they did not collect.",
    ]
    for collection in stale_collections:
        limitations.append(
            f"{_collection_note(collection, as_of)}. Binding evidence from this workspace is "
            "14 days older than the evaluation time, so both the bindings it shows and the "
            "bindings it does not show describe the state as last refreshed, not as of the "
            "evaluation time."
        )

    return {
        "question": "A",
        "asked": (
            "which EC2 instances are observed as running in production for this tenant, and "
            "what evidence exists of a managed-resource binding in the supplied Terraform state"
        ),
        "query_scope": {**scope.to_dict(), "environment": environment},
        "evaluation_time": as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "terraform_evidence_coverage": {
            "state": tf_state,
            "collections": tf_collections,
            "how_read": {
                "complete": "absence of a binding is evidence within the declared scope",
                "complete_stale": "absence of a binding is evidence within the declared scope, "
                "but the scope was observed beyond its freshness budget",
                "unavailable": "no claim about bindings is possible; answered 'unavailable'",
            },
        },
        "summary": {
            "instances_observed_running": len(population),
            "managed_binding_found": tally[EvidenceStatus.FOUND.value],
            "no_binding_found_in_supplied_scope": tally[
                EvidenceStatus.NOT_FOUND_IN_SUPPLIED_SCOPE.value
            ],
            "binding_evidence_unavailable": tally[EvidenceStatus.UNAVAILABLE.value],
        },
        "results": results,
        "state_records_without_matching_inventory_observation": counterfactuals,
        "limitations": limitations,
    }


def _negative_binding_status(tf_state: str) -> str:
    if tf_state == "unavailable":
        return EvidenceStatus.UNAVAILABLE.value
    return EvidenceStatus.NOT_FOUND_IN_SUPPLIED_SCOPE.value


def _scope_qualifier(tf_state: str, collections: list[str]) -> str:
    if tf_state == "complete_stale":
        return (
            f" within {', '.join(collections)}, which is complete for this scope but was "
            "observed beyond its freshness budget"
        )
    if tf_state == "complete":
        return f" within {', '.join(collections)}, complete for this scope"
    return ""


def _binding_dict(graph: ContextGraph, scope: QueryScope, edge: Edge) -> dict[str, Any]:
    source = graph.entities[edge.src_id]
    attributes = source.attributes
    return {
        "workspace_id": attributes.get("workspace_id"),
        "terraform_address": attributes.get("address"),
        "mode": attributes.get("mode"),
        "state_lineage": attributes.get("lineage"),
        "state_serial": attributes.get("serial"),
        "referenced_arn": attributes.get("provider_arn"),
        "state_tag_operator_team": attributes.get("source_operator_team"),
        "basis": edge.basis,
        "qualifiers": edge.qualifiers,
        "observed_at": edge.evidence[-1].observed_at if edge.evidence else None,
        "evidence": _evidence_dicts(graph, scope, edge.evidence),
    }


def answer_application_context(
    graph: ContextGraph,
    scope: QueryScope,
    as_of: datetime,
    application_name: str,
) -> dict[str, Any]:
    """Question B: catalog application, declared dependencies, workload-to-cloud path."""
    apps = [
        entity
        for entity in graph.entities_in(scope, [EntityKind.CATALOG_APPLICATION])
        if entity.attributes.get("service_name") == application_name
    ]
    if not apps:
        return {
            "question": "B",
            "query_scope": scope.to_dict(),
            "evaluation_time": as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "not_found_in_supplied_scope",
            "results": [],
            "limitations": [
                f"no catalog application named {application_name!r} in this tenant and environment"
            ],
        }
    results = [
        _application_result(graph, scope, app, application_name, as_of) for app in apps
    ]
    return {
        "question": "B",
        "asked": (
            "for the production catalog application, show declared dependencies and the "
            "supported path from workloads through Kubernetes Nodes to cloud resources, and "
            "identify the application team and any separately evidenced infrastructure operator"
        ),
        "query_scope": {**scope.to_dict(), "application_name": application_name},
        "evaluation_time": as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "applications_matched": len(results),
            "note": "matched on catalog service_name within the tenant and environment; "
            "kubernetes label and display-name similarity is not treated as identity",
        },
        "results": results,
        "limitations": [
            "A workload running on a Node that is backed by an instance establishes placement "
            "only. It does not establish that the workload depends on that instance's other "
            "workloads, nor that the instance's operator team is responsible for the "
            "application.",
            "Service, endpoint, readiness and traffic relationships are outside the supplied "
            "extract, so a declared catalog dependency is the only dependency kind this answer "
            "can show.",
        ],
    }


def _application_result(
    graph: ContextGraph,
    scope: QueryScope,
    app: Entity,
    application_name: str,
    as_of: datetime,
) -> dict[str, Any]:
    workload_edges = graph.edges_from(scope, app.entity_id, [EdgeKind.RUNS_WORKLOAD])
    dependency_edges = graph.edges_from(scope, app.entity_id, [EdgeKind.DECLARES_DEPENDENCY])
    hops, terminated = _walk_workloads(graph, scope, workload_edges)
    reached_instances = sorted(
        {
            hop["to"]
            for hop in hops
            if hop["kind"] == EdgeKind.HOSTS.value
        }
    )
    return {
        "application": {
            "entity_id": app.entity_id,
            "service_id": app.attributes["service_id"],
            "service_name": app.attributes["service_name"],
            "environment": app.attributes["environment"],
            "application_team": {
                "value": app.attributes.get("application_team"),
                "kind": "source statement",
                "meaning": "the catalog's statement of application-team responsibility",
                "evidence": _evidence_dicts(graph, scope, app.evidence),
            },
        },
        "declared_dependencies": _dependencies(graph, scope, app, dependency_edges),
        "workload_path": {
            "hops": hops,
            "workloads_found": sorted(
                {hop["to"] for hop in hops if hop["kind"] == EdgeKind.SCHEDULED_ON.value}
            ),
            "cloud_resources_reached": reached_instances,
            "ends": _path_ends(graph, scope, reached_instances, as_of),
            "termination_points": terminated,
        },
        "responsibility": _responsibility(graph, scope, app, reached_instances),
        "not_established": _not_established(graph, scope, app, application_name, hops),
    }


def _walk_workloads(
    graph: ContextGraph, scope: QueryScope, workload_edges: list[Edge]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deployment -> controlled ReplicaSets -> Pods -> Node -> cloud resource."""
    hops: list[dict[str, Any]] = []
    terminated: list[dict[str, Any]] = []
    pending = [edge.dst_id for edge in workload_edges]
    for edge in workload_edges:
        hops.append(_hop(edge))
    seen: set[str] = set()
    while pending:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        entity = graph.entities.get(current)
        if entity is None:
            continue
        for edge in graph.edges_to(scope, current, [EdgeKind.CONTROLLED_BY]):
            hops.append(_hop(edge))
            pending.append(edge.src_id)
        if entity.kind is EntityKind.K8S_POD:
            for edge in graph.edges_from(scope, current, [EdgeKind.SCHEDULED_ON]):
                hops.append(_hop(edge))
                pending.append(edge.dst_id)
        if entity.kind is EntityKind.K8S_NODE:
            hosts = graph.edges_from(scope, current, [EdgeKind.HOSTS])
            for edge in hosts:
                hops.append(_hop(edge))
                pending.append(edge.dst_id)
            for link in graph.unresolved_from(scope, current):
                if link.kind is EdgeKind.HOSTS:
                    terminated.append(_termination(entity, link))
    return hops, terminated


def _hop(edge: Edge) -> dict[str, Any]:
    return {
        "from": edge.src_id,
        "to": edge.dst_id,
        "kind": edge.kind.value,
        "basis": edge.basis,
        "meaning": EDGE_MEANING[edge.kind],
        "qualifiers": edge.qualifiers,
        "evidence_ref": edge.evidence[-1].record_ref if edge.evidence else None,
        "observed_at": edge.evidence[-1].observed_at if edge.evidence else None,
    }


def _path_ends(
    graph: ContextGraph,
    scope: QueryScope,
    reached_instances: list[str],
    as_of: datetime,
) -> list[dict[str, Any]]:
    """Where the substantiated path stops, and what is and is not known there."""
    out: list[dict[str, Any]] = []
    for entity_id in reached_instances:
        bindings = graph.edges_to(scope, entity_id, [EdgeKind.MANAGED_BINDING])
        out.append(
            {
                "at": entity_id,
                "last_relationship": EdgeKind.HOSTS.value,
                "why_it_ends": "the extract supplies no object that a cloud resource points at "
                "next: VPCs, subnets, network attachments and volume mappings are outside the "
                "selected fields, so no further hop is defined rather than an empty one",
                "terraform_evidence": [
                    {
                        "status": EvidenceStatus.FOUND.value,
                        "workspace_id": graph.entities[binding.src_id].attributes.get("workspace_id"),
                        "address": graph.entities[binding.src_id].attributes.get("address"),
                        "observed_at": binding.evidence[-1].observed_at if binding.evidence else None,
                        "qualifiers": binding.qualifiers,
                    }
                    for binding in bindings
                ]
                or [
                    {
                        "status": _negative_binding_status(
                            terraform_scope_covers(
                                graph,
                                scope,
                                as_of,
                                str(scope.environment),
                                "aws_instance",
                            )[0]
                        ),
                        "why": "reached by placement only; nothing in the supplied state "
                        "references this ARN",
                    }
                ],
            }
        )
    return out


def _termination(source: Entity, link) -> dict[str, Any]:
    return {
        "at": source.entity_id,
        "attempted": link.kind.value,
        "target": link.target,
        "state": link.state.value,
        "why": link.reason,
        "candidates_reported_only": link.candidates,
        "resolving_evidence": link.resolving_evidence,
        "evidence_ref": link.evidence[-1].record_ref if link.evidence else None,
    }


def _dependencies(
    graph: ContextGraph, scope: QueryScope, app: Entity, edges: list[Edge]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for edge in edges:
        target = graph.entities[edge.dst_id]
        bindings = graph.edges_to(scope, target.entity_id, [EdgeKind.MANAGED_BINDING])
        out.append(
            {
                "status": EvidenceStatus.FOUND.value,
                "kind": "catalog source statement resolved to an observed resource",
                "target_entity_id": target.entity_id,
                "arn": target.attributes.get("arn"),
                "target_environment": target.environment,
                "target_status": target.attributes.get("status"),
                "operator_team_statement": target.attributes.get("source_operator_team"),
                "target_managed_by_terraform": [
                    {
                        "workspace_id": graph.entities[binding.src_id].attributes.get("workspace_id"),
                        "terraform_address": graph.entities[binding.src_id].attributes.get("address"),
                        "observed_at": binding.evidence[-1].observed_at if binding.evidence else None,
                        "qualifiers": binding.qualifiers,
                        "evidence_ref": binding.evidence[-1].record_ref if binding.evidence else None,
                    }
                    for binding in bindings
                ],
                "meaning": "the catalog states this dependency; the model did not infer it from "
                "co-location or naming",
                "evidence": _evidence_dicts(graph, scope, edge.evidence),
            }
        )
    for link in graph.unresolved_from(scope, app.entity_id):
        if link.kind is not EdgeKind.DECLARES_DEPENDENCY:
            continue
        out.append(
            {
                "status": link.state.value,
                "kind": "catalog source statement that could not be resolved",
                "arn": link.target,
                "why": link.reason,
                "resolving_evidence": link.resolving_evidence,
                "evidence": _evidence_dicts(graph, scope, link.evidence),
            }
        )
    return sorted(out, key=lambda item: str(item.get("arn")))


def _responsibility(
    graph: ContextGraph, scope: QueryScope, app: Entity, reached_instances: list[str]
) -> dict[str, Any]:
    operator_statements: list[dict[str, Any]] = []
    for entity_id in reached_instances:
        entity = graph.entities.get(entity_id)
        if entity is None:
            continue
        cloud_value = entity.attributes.get("source_operator_team")
        for evidence in [e for e in entity.evidence if e.attribute == "operator_team"]:
            operator_statements.append(
                {
                    "about": entity_id,
                    "value": cloud_value,
                    "source": "cloud inventory tag Tags.operator_team",
                    "kind": "source statement",
                    "observed_at": evidence.observed_at,
                    "freshness": evidence.freshness,
                    "record_ref": evidence.record_ref,
                    "statement": evidence.statement,
                }
            )
        for binding in graph.edges_to(scope, entity_id, [EdgeKind.MANAGED_BINDING]):
            state_entity = graph.entities[binding.src_id]
            state_value = state_entity.attributes.get("source_operator_team")
            for evidence in [
                item for item in state_entity.evidence if item.attribute == "operator_team"
            ]:
                operator_statements.append(
                    {
                        "about": entity_id,
                        "value": state_value,
                        "source": "terraform state tag values.tags.operator_team",
                        "kind": "source statement",
                        "observed_at": evidence.observed_at,
                        "freshness": evidence.freshness,
                        "record_ref": evidence.record_ref,
                        "statement": evidence.statement,
                        "qualifiers": binding.qualifiers,
                    }
                )
    conflicts = [
        conflict.to_dict()
        for conflict in graph.conflicts_for(scope)
        if conflict.subject_id in reached_instances
    ]
    return {
        "application_team": {
            "value": app.attributes.get("application_team"),
            "evidenced_by": "catalog owner_team column",
            "meaning": "responsibility for the application as declared by the service catalog",
        },
        "infrastructure_operator": {
            "values": sorted(
                operator_statements, key=lambda item: (item["about"], str(item["value"]))
            ),
            "distinct_teams": sorted({str(item["value"]) for item in operator_statements}),
            "kind": "source statements, not a derived conclusion",
            "meaning": "each value is what one source stated about infrastructure operation for "
            "the instance the workload runs on, at that source's observation time",
            "conflicts": conflicts,
            "unproven": "which team operates the application's own deployment pipeline is not "
            "stated by any supplied source",
        },
    }


def _not_established(
    graph: ContextGraph,
    scope: QueryScope,
    app: Entity,
    application_name: str,
    hops: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Claims a careless reader of this answer could make, and why they are not supported."""
    out: list[dict[str, Any]] = []
    node_ids = sorted({hop["to"] for hop in hops if hop["kind"] == EdgeKind.SCHEDULED_ON.value})
    for node_id in node_ids:
        co_located = sorted(
            {
                edge.src_id
                for edge in graph.edges_to(scope, node_id, [EdgeKind.SCHEDULED_ON])
                if _belongs_to_other_app(graph, edge.src_id, application_name)
            }
        )
        if co_located:
            out.append(
                {
                    "claim": f"workloads {', '.join(co_located)} depend on {application_name} "
                    f"(or the reverse), because they share Node {node_id}",
                    "status": "not supported",
                    "why": "the only evidence is two pods scheduled onto the same node. "
                    "Co-location is placement; a dependency claim needs a catalog statement or a "
                    "service/endpoint record, and neither is present.",
                    "evidence_ref": next(
                        (hop["evidence_ref"] for hop in hops if hop["to"] == node_id), None
                    ),
                }
            )
    lookalikes = sorted(
        entity.entity_id
        for entity in graph.entities_in(scope, [EntityKind.CLOUD_INSTANCE])
        if entity.attributes.get("display_name") == application_name
    )
    if lookalikes:
        out.append(
            {
                "claim": f"{', '.join(lookalikes)} is a workload or dependency of "
                f"the {application_name} application",
                "status": "not supported",
                "why": "the match is on tags.Name, a display label. The catalog workload "
                "reference for this application names a Kubernetes Deployment, not this "
                "instance, and no stated key connects the instance to the application.",
                "evidence_ref": next(
                    (
                        evidence.record_ref
                        for entity_id in lookalikes
                        for evidence in graph.entities[entity_id].evidence
                    ),
                    None,
                ),
            }
        )
    for entity_id in sorted({hop["to"] for hop in hops if hop["kind"] == EdgeKind.HOSTS.value}):
        if not graph.edges_to(scope, entity_id, [EdgeKind.MANAGED_BINDING]):
            out.append(
                {
                    "claim": f"{entity_id} is unmanaged, or should be removed",
                    "status": "not established",
                    "why": "the absence of a managed binding in the supplied state says only "
                    "that this state, at its observation time, did not reference the ARN. "
                    "Management in another workspace is outside the supplied scope.",
                }
            )
    return out


def _belongs_to_other_app(graph: ContextGraph, pod_id: str, application_name: str) -> bool:
    pod = graph.entities.get(pod_id)
    if pod is None:  # unreachable through a scoped traversal; treated as another workload
        return True
    return pod.attributes.get("labels", {}).get("app") != application_name


EDGE_MEANING = {
    EdgeKind.RUNS_WORKLOAD: "the catalog's declared workload reference for this application",
    EdgeKind.CONTROLLED_BY: "Kubernetes controller ownership: the source object controls the "
    "lifecycle of the target, stated by an ownerReference UID",
    EdgeKind.SCHEDULED_ON: "placement only: this pod is scheduled onto this node",
    EdgeKind.HOSTS: "the node object's provider reference identifies this cloud instance",
    EdgeKind.DECLARES_DEPENDENCY: "the catalog's own dependency statement",
}
