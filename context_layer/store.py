"""The graph store and the only query interface consumers are allowed to use.

Tenant enforcement lives here rather than in each question: every entity, edge
and piece of evidence carries the tenant of the trusted manifest collection that
supplied it, and the store refuses to return anything outside the caller's
``QueryScope``. Serialisation re-checks every evidence record, so a leaked
cross-tenant reference fails loudly instead of appearing in an answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator

from .model import (
    Collection,
    Conflict,
    Edge,
    EdgeKind,
    Entity,
    EntityKind,
    Evidence,
    UnresolvedLink,
)


class TenantLeakError(RuntimeError):
    """A result would expose a record from outside the requested tenant."""


@dataclass(frozen=True)
class QueryScope:
    tenant_id: str
    environment: str | None = None
    label: str = ""

    def contains(self, tenant_id: str) -> bool:
        return tenant_id == self.tenant_id

    def to_dict(self) -> dict[str, str]:
        out = {"tenant_id": self.tenant_id}
        if self.environment is not None:
            out["environment"] = self.environment
        if self.label:
            out["label"] = self.label
        return out


class ContextGraph:
    def __init__(self) -> None:
        self.collections: dict[str, Collection] = {}
        self.entities: dict[str, Entity] = {}
        self.edges: list[Edge] = []
        self.unresolved: list[UnresolvedLink] = []
        self.conflicts: list[Conflict] = []
        # Resolution indexes. Keys always begin with tenant, so a cross-tenant
        # join is not merely filtered out later -- it cannot be formed.
        self.by_arn: dict[str, str] = {}
        self.by_k8s_name: dict[str, str] = {}
        self.by_k8s_uid: dict[str, str] = {}
        self.by_instance_key: dict[str, str] = {}

    # -- construction -----------------------------------------------------

    def add_entity(self, entity: Entity) -> Entity:
        existing = self.entities.get(entity.entity_id)
        if existing is not None:
            if existing.kind is not entity.kind:
                raise ValueError(f"identity {entity.entity_id} reused for two kinds")
            for evidence in entity.evidence:
                existing.add_evidence(evidence)
            return existing
        self.entities[entity.entity_id] = entity
        return entity

    def add_edge(self, edge: Edge) -> Edge:
        for endpoint in (edge.src_id, edge.dst_id):
            self.require_tenant(edge.tenant_id, endpoint)
        identity = (edge.kind, edge.src_id, edge.dst_id, edge.basis)
        for existing in self.edges:
            if (existing.kind, existing.src_id, existing.dst_id, existing.basis) != identity:
                continue
            for evidence in edge.evidence:
                if evidence not in existing.evidence:
                    existing.evidence.append(evidence)
            for qualifier in edge.qualifiers:
                if qualifier not in existing.qualifiers:
                    existing.qualifiers.append(qualifier)
            return existing
        self.edges.append(edge)
        return edge

    def add_conflict(self, conflict: Conflict) -> Conflict:
        identity = (conflict.subject_id, conflict.attribute, tuple(
            (statement.record_ref, statement.statement) for statement in conflict.statements
        ))
        for existing in self.conflicts:
            existing_identity = (existing.subject_id, existing.attribute, tuple(
                (statement.record_ref, statement.statement) for statement in existing.statements
            ))
            if existing_identity == identity:
                return existing
        self.conflicts.append(conflict)
        return conflict

    def add_unresolved(self, link: UnresolvedLink) -> UnresolvedLink:
        self.require_tenant(link.tenant_id, link.from_id)
        identity = (link.kind, link.from_id, link.target)
        for existing in self.unresolved:
            if (existing.kind, existing.from_id, existing.target) != identity:
                continue
            for evidence in link.evidence:
                if evidence not in existing.evidence:
                    existing.evidence.append(evidence)
            for candidate in link.candidates:
                if candidate not in existing.candidates:
                    existing.candidates.append(candidate)
            return existing
        self.unresolved.append(link)
        return link

    def require_tenant(self, tenant_id: str, entity_id: str) -> Entity:
        entity = self.entities.get(entity_id)
        if entity is None:
            raise KeyError(f"unknown entity {entity_id}")
        if entity.tenant_id != tenant_id:
            raise TenantLeakError(
                f"edge for tenant {tenant_id} points at {entity.tenant_id} entity {entity_id}"
            )
        return entity

    # -- scoped reads -----------------------------------------------------

    def entities_in(
        self,
        scope: QueryScope,
        kinds: Iterable[EntityKind] = (),
    ) -> list[Entity]:
        wanted = tuple(kinds)
        out = [
            entity
            for entity in self.entities.values()
            if entity.tenant_id == scope.tenant_id
            and (scope.environment is None or entity.environment == scope.environment)
            and (not wanted or entity.kind in wanted)
        ]
        return sorted(out, key=lambda e: e.entity_id)

    def get(self, scope: QueryScope, entity_id: str) -> Entity | None:
        entity = self.entities.get(entity_id)
        if entity is None or entity.tenant_id != scope.tenant_id:
            return None
        if scope.environment is not None and entity.environment != scope.environment:
            return None
        return entity

    def edges_from(
        self,
        scope: QueryScope,
        entity_id: str,
        kinds: Iterable[EdgeKind] = (),
    ) -> list[Edge]:
        wanted = tuple(kinds)
        return sorted(
            (
                edge
                for edge in self.edges
                if edge.src_id == entity_id
                and edge.tenant_id == scope.tenant_id
                and (not wanted or edge.kind in wanted)
            ),
            key=lambda e: (e.kind.value, e.dst_id),
        )

    def edges_to(
        self,
        scope: QueryScope,
        entity_id: str,
        kinds: Iterable[EdgeKind] = (),
    ) -> list[Edge]:
        wanted = tuple(kinds)
        return sorted(
            (
                edge
                for edge in self.edges
                if edge.dst_id == entity_id
                and edge.tenant_id == scope.tenant_id
                and (not wanted or edge.kind in wanted)
            ),
            key=lambda e: (e.kind.value, e.src_id),
        )

    def unresolved_from(self, scope: QueryScope, entity_id: str) -> list[UnresolvedLink]:
        return sorted(
            (
                link
                for link in self.unresolved
                if link.from_id == entity_id and link.tenant_id == scope.tenant_id
            ),
            key=lambda link: (link.kind.value, link.target),
        )

    def conflicts_for(self, scope: QueryScope) -> list[Conflict]:
        out = [
            conflict
            for conflict in self.conflicts
            if self.get(scope, conflict.subject_id) is not None
        ]
        return sorted(out, key=lambda c: (c.subject_id, c.attribute))

    def collections_in(
        self,
        scope: QueryScope,
        family: str | None = None,
    ) -> Iterator[Collection]:
        for collection in sorted(self.collections.values(), key=lambda c: c.snapshot_id):
            if collection.tenant_id != scope.tenant_id:
                continue
            if scope.environment is not None and collection.environment != scope.environment:
                continue
            if family is not None and collection.source_family.value != family:
                continue
            yield collection

    # -- output guarding --------------------------------------------------

    def check_evidence(self, scope: QueryScope, items: Iterable[Evidence]) -> list[Evidence]:
        material = list(items)
        for evidence in material:
            if not scope.contains(evidence.tenant_id):
                raise TenantLeakError(
                    f"answer for tenant {scope.tenant_id} would cite "
                    f"{evidence.tenant_id} record {evidence.record_ref}"
                )
        return material

    def all_evidence(self) -> list[Evidence]:
        out: list[Evidence] = []
        for entity in self.entities.values():
            out.extend(entity.evidence)
        for edge in self.edges:
            out.extend(edge.evidence)
        for link in self.unresolved:
            out.extend(link.evidence)
        for conflict in self.conflicts:
            out.extend(conflict.statements)
        return out

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entity in self.entities.values():
            counts[entity.kind.value] = counts.get(entity.kind.value, 0) + 1
        for edge in self.edges:
            counts[f"edge:{edge.kind.value}"] = counts.get(f"edge:{edge.kind.value}", 0) + 1
        counts["unresolved_links"] = len(self.unresolved)
        counts["conflicts"] = len(self.conflicts)
        return counts
