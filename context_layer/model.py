"""Typed context model: entities, evidence-carrying relationships, qualified uncertainty.

Design contract
---------------
Identity rule: an entity's identifier is only meaningful inside the scope the
manifest declares for the collection that supplied it. Two records are the same
entity only when every component of the scoped key agrees, including tenant.
Nothing is merged on display name, private IP address, label, or bare resource
identifier -- those produce an issue, never an edge.

Evidence rule: every attribute and relationship claim carries the record that
stated it, plus that collection's observation time and freshness. A relationship
is asserted only by a join key the source itself states (an ARN, a Kubernetes
UID, a Node providerID, a catalog workload reference).

Uncertainty rule: absence is typed. ``found``, ``not_found_in_supplied_scope``
(a complete collection covered the scope and did not report it) and
``unavailable`` (no collection covered the scope) are three different answers
and are never collapsed into one another.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SourceFamily(str, Enum):
    AWS = "aws"
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    CATALOG = "catalog"


class EntityKind(str, Enum):
    CLOUD_INSTANCE = "cloud_instance"
    CLOUD_DATABASE = "cloud_database"
    TERRAFORM_RESOURCE = "terraform_resource"
    K8S_DEPLOYMENT = "k8s_deployment"
    K8S_REPLICASET = "k8s_replicaset"
    K8S_POD = "k8s_pod"
    K8S_NODE = "k8s_node"
    CATALOG_APPLICATION = "catalog_application"


class EdgeKind(str, Enum):
    """Directed relationships. The direction and the stated key are the meaning."""

    # terraform resource -> cloud resource; key: values.arn, mode == managed
    MANAGED_BINDING = "managed_binding"
    # terraform resource -> cloud resource; key: values.arn, mode == data.
    # A data source reads an object; it does not manage it.
    DATA_REFERENCE = "data_reference"
    # pod -> node; key: pod.spec.nodeName within the same cluster
    SCHEDULED_ON = "scheduled_on"
    # controlled object -> controlling object; key: ownerReferences[].uid
    CONTROLLED_BY = "controlled_by"
    # node -> cloud instance; key: spec.providerID resolved with cluster account
    HOSTS = "hosts"
    # catalog application -> k8s deployment; key: cluster_id/namespace/deployment_name
    RUNS_WORKLOAD = "runs_workload"
    # catalog application -> cloud resource; key: declared_dependency_arn
    DECLARES_DEPENDENCY = "declares_dependency"


class EvidenceStatus(str, Enum):
    """The three-way answer vocabulary. Never collapse these."""

    FOUND = "found"
    NOT_FOUND_IN_SUPPLIED_SCOPE = "not_found_in_supplied_scope"
    UNAVAILABLE = "unavailable"


class LinkState(str, Enum):
    ESTABLISHED = "established"
    UNRESOLVED = "unresolved"
    AMBIGUOUS = "ambiguous"
    # A complete collection covered this scope and did not report the target:
    # evidence of absence within that scope, not a missing join key.
    NOT_IN_SUPPLIED_SCOPE = "not_in_supplied_scope"
    SCOPE_UNAVAILABLE = "scope_unavailable"


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse a supplied timestamp. UTC offsets are significant and preserved."""
    if value is None:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp is not offset-aware: {value!r}")
    return parsed


def format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Collection:
    """One logical collection from manifest.snapshots, with derived freshness."""

    snapshot_id: str
    source_family: SourceFamily
    source_instance_id: str
    tenant_id: str
    payload_path: str | None
    observed_at: datetime | None
    exported_at: datetime | None
    freshness_budget_seconds: int
    status: str
    coverage: str
    scope: dict[str, Any]

    @property
    def available(self) -> bool:
        return self.status == "success" and self.payload_path is not None

    @property
    def complete(self) -> bool:
        return self.coverage == "complete"

    @property
    def environment(self) -> str | None:
        value = self.scope.get("environment")
        return value if isinstance(value, str) else None

    def age_seconds(self, as_of: datetime) -> int | None:
        if self.observed_at is None:
            return None
        return int((as_of - self.observed_at).total_seconds())

    def freshness(self, as_of: datetime) -> str:
        """Equality with the budget is within budget (EXTRACT_NOTES.md)."""
        age = self.age_seconds(as_of)
        if age is None:
            return "not_observed"
        return "fresh" if age <= self.freshness_budget_seconds else "stale"

    def describe_freshness(self, as_of: datetime) -> str:
        age = self.age_seconds(as_of)
        if age is None:
            return f"{self.snapshot_id}: no observation time (status={self.status})"
        return (
            f"{self.snapshot_id}: observed {format_timestamp(self.observed_at)}, "
            f"age {age}s, budget {self.freshness_budget_seconds}s -> "
            f"{self.freshness(as_of)}"
        )


@dataclass(frozen=True)
class Evidence:
    """One source statement, tied to the record that made it.

    ``statement`` is what the source asserted as supplied. Conclusions derived by
    this code belong on edges or in answers, never here.
    """

    tenant_id: str
    environment: str
    snapshot_id: str
    source_family: str
    source_instance_id: str
    record_ref: str
    observed_at: str | None
    freshness: str
    coverage: str
    statement: str
    attribute: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "record_ref": self.record_ref,
            "snapshot_id": self.snapshot_id,
            "source_family": self.source_family,
            "source_instance_id": self.source_instance_id,
            "observed_at": self.observed_at,
            "freshness": self.freshness,
            "coverage": self.coverage,
            "statement": self.statement,
        }
        if self.attribute is not None:
            out["asserts_attribute"] = self.attribute
        return out


@dataclass
class Entity:
    entity_id: str
    kind: EntityKind
    tenant_id: str
    environment: str
    scope: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)

    def add_evidence(self, evidence: Evidence) -> None:
        if evidence.tenant_id != self.tenant_id:
            raise ValueError(
                f"refusing to attach {evidence.tenant_id} evidence to "
                f"{self.tenant_id} entity {self.entity_id}"
            )
        if evidence not in self.evidence:
            self.evidence.append(evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "kind": self.kind.value,
            "scope": self.scope,
            "attributes": self.attributes,
            "evidence": [e.to_dict() for e in sorted_evidence(self.evidence)],
        }


@dataclass
class Edge:
    """An established relationship. ``basis`` names the key that states it."""

    kind: EdgeKind
    src_id: str
    dst_id: str
    basis: str
    tenant_id: str
    environment: str
    evidence: list[Evidence] = field(default_factory=list)
    qualifiers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "from": self.src_id,
            "to": self.dst_id,
            "basis": self.basis,
            "qualifiers": self.qualifiers,
            "evidence": [e.to_dict() for e in sorted_evidence(self.evidence)],
        }


@dataclass
class UnresolvedLink:
    """A relationship the supplied evidence could not establish, and why.

    Deliberately not an Edge: an unresolved link must not be traversable as if it
    were a fact.
    """

    kind: EdgeKind
    from_id: str
    target: str
    tenant_id: str
    environment: str
    state: LinkState
    reason: str
    candidates: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    resolving_evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "from": self.from_id,
            "target": self.target,
            "state": self.state.value,
            "reason": self.reason,
            "candidates": self.candidates,
            "resolving_evidence": self.resolving_evidence,
            "evidence": [e.to_dict() for e in sorted_evidence(self.evidence)],
        }


@dataclass
class Conflict:
    """Two sources disagreeing about one attribute of one entity."""

    subject_id: str
    attribute: str
    statements: list[Evidence]
    note: str
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "attribute": self.attribute,
            "resolved": self.resolved,
            "statements": [s.to_dict() for s in sorted_evidence(self.statements)],
            "note": self.note,
        }


def sorted_evidence(items: list[Evidence]) -> list[Evidence]:
    """Stable ordering so a rebuild is byte-identical."""
    return sorted(items, key=lambda e: (e.record_ref, e.snapshot_id, e.statement))
