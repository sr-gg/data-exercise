"""Identity keys and cross-source resolution.

Every rule that decides whether two records describe the same thing lives here,
so the questions cannot quietly re-derive identity for themselves.

Identity keys (tenant is a component of all of them because the manifest is
trusted tenant context):

===============================================  ==============================
Entity                                           Key
===============================================  ==============================
EC2 instance                                     tenant + account + region + InstanceId
RDS instance                                     tenant + DBInstanceArn
Terraform resource record                        tenant + workspace_id + address
Kubernetes object (current name)                 tenant + cluster_id + kind + namespace + name
Kubernetes object (incarnation)                  tenant + cluster_id + metadata.uid
Catalog application                              tenant + service_id + declared environment
===============================================  ==============================

Deliberately *not* identity keys: ``Name``/``tags.Name``, private IP addresses,
labels, ``DBInstanceIdentifier`` alone, and Terraform addresses alone. Each of
those is shared by unrelated objects in the supplied data.

A relationship is created only when the source states the key that justifies it.
Similarity without a stated key produces an UnresolvedLink or an Issue, never an
Edge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .ingest import LoadedInputs, RawRecord, tag_mapping
from .model import (
    Collection,
    Conflict,
    Edge,
    EdgeKind,
    Entity,
    EntityKind,
    Evidence,
    LinkState,
    SourceFamily,
    UnresolvedLink,
    format_timestamp,
)
from .store import ContextGraph, QueryScope

K8S_KIND_ENTITY = {
    "Deployment": EntityKind.K8S_DEPLOYMENT,
    "ReplicaSet": EntityKind.K8S_REPLICASET,
    "Pod": EntityKind.K8S_POD,
    "Node": EntityKind.K8S_NODE,
}

NAMESPACELESS = {"Node", "Namespace", "ClusterRole", "PersistentVolume"}


@dataclass
class Issue:
    """One material limitation, with the evidence that would resolve it."""

    category: str
    subject: str
    summary: str
    detail: str
    resolving_evidence: str
    record_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "subject": self.subject,
            "summary": self.summary,
            "detail": self.detail,
            "resolving_evidence": self.resolving_evidence,
            "record_refs": sorted(self.record_refs),
        }


def ec2_arn(region: str, account_id: str, instance_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"


class Resolver:
    def __init__(self, inputs: LoadedInputs) -> None:
        self.inputs = inputs
        self.graph = ContextGraph()
        self.issues: list[Issue] = []
        for snapshot_id, collection in inputs.manifest.collections.items():
            self.graph.collections[snapshot_id] = collection

    # -- helpers ---------------------------------------------------------

    def evidence(
        self,
        record: RawRecord,
        statement: str,
        environment: str,
        attribute: str | None = None,
    ) -> Evidence:
        collection = record.collection
        return Evidence(
            tenant_id=collection.tenant_id,
            environment=environment,
            snapshot_id=collection.snapshot_id,
            source_family=collection.source_family.value,
            source_instance_id=collection.source_instance_id,
            record_ref=record.record_ref,
            observed_at=format_timestamp(collection.observed_at),
            freshness=collection.freshness(self.inputs.as_of),
            coverage=collection.coverage,
            statement=statement,
            attribute=attribute,
        )

    def attach_tag_evidence(
        self,
        entity_id: str,
        record: RawRecord,
        environment: str,
        tags: dict[str, str],
        render: str,
    ) -> None:
        """One evidence item per tag, so an attribute claim cites its own statement."""
        entity = self.graph.entities[entity_id]
        for key in sorted(tags):
            entity.add_evidence(
                self.evidence(
                    record, render.format(key=key, value=tags[key]), environment, attribute=key
                )
            )

    def add_issue(self, category: str, subject: str, summary: str, detail: str,
                  resolving: str, refs: list[str] | None = None) -> None:
        self.issues.append(
            Issue(
                category=category,
                subject=subject,
                summary=summary,
                detail=detail,
                resolving_evidence=resolving,
                record_refs=refs or [],
            )
        )

    def aws_scope_covers(self, tenant: str, environment: str, resource_type: str) -> tuple[str, list[str]]:
        return cloud_scope_covers(
            self.graph, QueryScope(tenant, environment), self.inputs.as_of, environment, resource_type
        )

    def terraform_scope_covers(
        self, tenant: str, environment: str, resource_type: str
    ) -> tuple[str, list[str]]:
        return terraform_scope_covers(
            self.graph, QueryScope(tenant, environment), self.inputs.as_of, environment, resource_type
        )

    def k8s_scope_covers(self, tenant: str, environment: str, cluster_id: str, kind: str) -> str:
        return k8s_scope_covers(
            self.graph, QueryScope(tenant, environment), cluster_id, kind
        )

    # -- cloud -----------------------------------------------------------

    def resolve_cloud(self) -> None:
        for record in self.inputs.aws_instances:
            collection = record.collection
            scope = collection.scope
            data = record.data
            account_id = scope["account_id"]
            region = scope["region"]
            environment = scope["environment"]
            instance_id = data["InstanceId"]
            tags = tag_mapping(data.get("Tags"))
            arn = ec2_arn(region, account_id, instance_id)
            entity_id = f"aws:ec2:{collection.tenant_id}:{account_id}:{region}:{instance_id}"
            attributes = {
                "instance_id": instance_id,
                "arn": arn,
                "account_id": account_id,
                "region": region,
                "availability_zone": tags.get("AvailabilityZone"),
                "state_name": data.get("State", {}).get("Name"),
                "private_ip": data.get("PrivateIpAddress"),
                "vpc_id": data.get("VpcId"),
                "display_name": tags.get("Name"),
                "source_environment_tag": tags.get("Environment"),
                "source_operator_team": tags.get("operator_team"),
            }
            statement = (
                f"InstanceId={instance_id} State.Name={attributes['state_name']} "
                f"PrivateIpAddress={attributes['private_ip']} VpcId={attributes['vpc_id']} "
                f"Tags={_fmt_tags(tags)}"
            )
            instance = self._merge(
                entity_id,
                EntityKind.CLOUD_INSTANCE,
                collection.tenant_id,
                environment,
                {
                    "tenant_id": collection.tenant_id,
                    "account_id": account_id,
                    "region": region,
                    "environment": environment,
                },
                attributes,
                self.evidence(record, statement, environment),
                record,
            )
            self.attach_tag_evidence(
                instance.entity_id, record, environment, tags, "Tags.{key}={value}"
            )
            self.graph.by_arn[f"{collection.tenant_id}#{arn}"] = entity_id
            self.graph.by_instance_key[
                f"{collection.tenant_id}#{account_id}#{region}#{instance_id}"
            ] = entity_id

        for record in self.inputs.aws_databases:
            collection = record.collection
            scope = collection.scope
            data = record.data
            environment = scope["environment"]
            arn = data["DBInstanceArn"]
            identifier = data["DBInstanceIdentifier"]
            tags = tag_mapping(data.get("Tags"))
            entity_id = f"aws:rds:{collection.tenant_id}:{arn}"
            attributes = {
                "db_instance_identifier": identifier,
                "arn": arn,
                "account_id": scope["account_id"],
                "region": scope["region"],
                "status": data.get("DBInstanceStatus"),
                "source_environment_tag": tags.get("Environment"),
                "source_operator_team": tags.get("operator_team"),
            }
            statement = (
                f"DBInstanceIdentifier={identifier} DBInstanceStatus={attributes['status']} "
                f"Tags={_fmt_tags(tags)}"
            )
            database = self._merge(
                entity_id,
                EntityKind.CLOUD_DATABASE,
                collection.tenant_id,
                environment,
                {
                    "tenant_id": collection.tenant_id,
                    "account_id": scope["account_id"],
                    "region": scope["region"],
                    "environment": environment,
                },
                attributes,
                self.evidence(record, statement, environment),
                record,
            )
            self.attach_tag_evidence(
                database.entity_id, record, environment, tags, "Tags.{key}={value}"
            )
            self.graph.by_arn[f"{collection.tenant_id}#{arn}"] = entity_id

        self._report_provider_object_shared_across_tenants()

    def _report_provider_object_shared_across_tenants(self) -> None:
        seen: dict[str, list[Entity]] = {}
        for entity in self.graph.entities.values():
            if entity.kind is not EntityKind.CLOUD_INSTANCE:
                continue
            key = (
                f"{entity.attributes['account_id']}#{entity.attributes['region']}"
                f"#{entity.attributes['instance_id']}"
            )
            seen.setdefault(key, []).append(entity)
        for key, entities in sorted(seen.items()):
            tenants = sorted({entity.tenant_id for entity in entities})
            if len(tenants) < 2:
                continue
            refs = [e.record_ref for entity in entities for e in entity.evidence]
            self.add_issue(
                "scope_collision",
                key,
                "one provider object is reported as complete under two tenants",
                (
                    f"account/region/InstanceId {key} is reported by tenants "
                    f"{', '.join(tenants)} with identical observed attributes. The manifest "
                    "is trusted for tenant context, so both collections are kept as separate "
                    "tenant-scoped entities and ownership is not adjudicated here."
                ),
                "an authoritative tenancy/ownership ledger (which internal tenant is "
                "entitled to this AWS account), or per-collection account->tenant mappings "
                "that do not overlap.",
                refs,
            )

    # -- terraform -------------------------------------------------------

    def resolve_terraform(self) -> None:
        for record in sorted(self.inputs.terraform_resources, key=lambda r: r.record_ref):
            collection = record.collection
            scope = collection.scope
            data = record.data
            tenant = collection.tenant_id
            environment = scope["environment"]
            workspace_id = scope.get("workspace_id", "")
            address = data["address"]
            mode = data["mode"]
            resource_type = data["type"]
            values = data.get("values", {})
            tags = dict(values.get("tags") or {})
            provider_id = values.get("id")
            provider_arn = values.get("arn")
            entity_id = f"tf:{tenant}:{workspace_id}:{address}"
            attributes = {
                "address": address,
                "mode": mode,
                "type": resource_type,
                "provider_id": provider_id,
                "provider_arn": provider_arn,
                "workspace_id": workspace_id,
                "lineage": record.parent.get("lineage"),
                "serial": record.parent.get("serial"),
                "state_tags": tags,
                "source_operator_team": tags.get("operator_team"),
            }
            statement = (
                f"mode={mode} type={resource_type} address={address} "
                f"values.id={provider_id} values.arn={provider_arn} "
                f"tags={_fmt_tags(tags)}"
            )
            resource = self._merge(
                entity_id,
                EntityKind.TERRAFORM_RESOURCE,
                tenant,
                environment,
                {
                    "tenant_id": tenant,
                    "workspace_id": workspace_id,
                    "account_id": scope.get("account_id"),
                    "region": scope.get("region"),
                    "environment": environment,
                },
                attributes,
                self.evidence(record, statement, environment),
                record,
            )
            self.attach_tag_evidence(
                resource.entity_id,
                record,
                environment,
                tags,
                "state values.tags.{key}={value}",
            )
            if provider_arn:
                self._link_terraform_to_cloud(record, entity_id, mode, resource_type, provider_arn)

    def _link_terraform_to_cloud(
        self, record: RawRecord, tf_entity_id: str, mode: str, resource_type: str, arn: str
    ) -> None:
        collection = record.collection
        tenant = collection.tenant_id
        environment = collection.scope["environment"]
        target_id = self.graph.by_arn.get(f"{tenant}#{arn}")
        edge_kind = (
            EdgeKind.MANAGED_BINDING if mode == "managed" else EdgeKind.DATA_REFERENCE
        )
        basis = f"terraform values.arn == provider ARN (mode={mode})"
        tf_evidence = self.evidence(
            record,
            f"{mode} state record {record.data['address']} references {arn}",
            environment,
        )
        if target_id is not None:
            qualifiers = []
            if collection.freshness(self.inputs.as_of) == "stale":
                qualifiers.append(
                    f"state_observed_{collection.freshness(self.inputs.as_of)}:"
                    f" {format_timestamp(collection.observed_at)}"
                )
            self.graph.add_edge(
                Edge(
                    kind=edge_kind,
                    src_id=tf_entity_id,
                    dst_id=target_id,
                    basis=basis,
                    tenant_id=tenant,
                    environment=environment,
                    evidence=[tf_evidence],
                    qualifiers=qualifiers,
                )
            )
            if mode == "managed":
                self._compare_operator_team(tf_entity_id, target_id, record)
            return

        state, coverage_ids = self.aws_scope_covers(tenant, environment, resource_type)
        if state == "unavailable":
            link_state = LinkState.SCOPE_UNAVAILABLE
            reason = (
                f"no supplied cloud inventory collection covers {resource_type} for "
                f"tenant {tenant} environment {environment}"
            )
            resolving = f"a complete {resource_type} inventory for this tenant and environment"
        else:
            link_state = LinkState.NOT_IN_SUPPLIED_SCOPE
            reason = (
                f"{arn} is referenced by state but no cloud record with that ARN appears in "
                f"the collection(s) {', '.join(coverage_ids)}, which are complete within "
                f"their declared scope as of their observation times"
            )
            resolving = (
                "a current cloud inventory observation for this scope: a resource present in "
                "state and absent from a complete inventory means either the state is out of "
                "date or the object is outside the inventory's account/region scope"
            )
        self.graph.add_unresolved(
            UnresolvedLink(
                kind=edge_kind,
                from_id=tf_entity_id,
                target=arn,
                tenant_id=tenant,
                environment=environment,
                state=link_state,
                reason=reason,
                evidence=[tf_evidence],
                resolving_evidence=resolving,
            )
        )
        self.add_issue(
            "unresolved_link",
            tf_entity_id,
            "state references a provider object the inventory does not report",
            reason,
            resolving,
            [record.record_ref],
        )

    def tag_evidence(self, entity: Entity, attribute: str) -> list[Evidence]:
        return [evidence for evidence in entity.evidence if evidence.attribute == attribute]

    def _compare_operator_team(self, tf_entity_id: str, cloud_entity_id: str, record: RawRecord) -> None:
        cloud = self.graph.entities[cloud_entity_id]
        tf = self.graph.entities[tf_entity_id]
        cloud_team = cloud.attributes.get("source_operator_team")
        tf_team = tf.attributes.get("source_operator_team")
        if tf_team is None or cloud_team == tf_team:
            return
        cloud_statements = self.tag_evidence(cloud, "operator_team")
        tf_statements = self.tag_evidence(tf, "operator_team")
        if not cloud_statements or not tf_statements:
            return
        cloud_statement = cloud_statements[-1]
        tf_statement = tf_statements[-1]
        self.graph.add_conflict(
            Conflict(
                subject_id=cloud_entity_id,
                attribute="operator_team",
                statements=[cloud_statement, tf_statement],
                note=(
                    f"the cloud tag says {cloud_team!r} and the Terraform state tag says "
                    f"{tf_team!r} for the same instance. Both are statements by their own "
                    "source at their own observation time; this model does not pick a winner."
                ),
            )
        )
        self.add_issue(
            "conflicting_observation",
            cloud_entity_id,
            "infrastructure operator disagreed between cloud tag and state tag",
            (
                f"{cloud_statement.record_ref} states {cloud_statement.statement} "
                f"(observed {cloud_statement.observed_at}); "
                f"{tf_statement.record_ref} states {tf_statement.statement} "
                f"(observed {tf_statement.observed_at})."
            ),
            "an authoritative team/ownership directory, or a change record explaining the "
            "rename or the legacy tag.",
            [cloud_statement.record_ref, tf_statement.record_ref],
        )

    # -- kubernetes ------------------------------------------------------

    def resolve_kubernetes(self) -> None:
        for record in sorted(self.inputs.k8s_objects, key=lambda r: r.record_ref):
            collection = record.collection
            data = record.data
            kind = data["kind"]
            metadata = data.get("metadata", {})
            namespace = metadata.get("namespace")
            if kind in NAMESPACELESS:
                namespace = None
            entity_kind = K8S_KIND_ENTITY.get(kind)
            if entity_kind is None:
                self.add_issue(
                    "unsupported_input",
                    kind,
                    "kind outside the documented extract contract",
                    f"{record.record_ref} has kind {kind}, which the extract notes do not define.",
                    "an updated extract-notes contract.",
                    [record.record_ref],
                )
                continue
            cluster_id = collection.scope["cluster_id"]
            tenant = collection.tenant_id
            environment = collection.scope["environment"]
            name = metadata["name"]
            entity_id = k8s_key(tenant, cluster_id, kind, namespace, name)
            attributes = {
                "kind": kind,
                "api_version": data.get("apiVersion"),
                "name": name,
                "namespace": namespace,
                "uid": metadata.get("uid"),
                "cluster_id": cluster_id,
                "labels": dict(metadata.get("labels") or {}),
                "owner_references": [
                    {
                        "kind": ref.get("kind"),
                        "name": ref.get("name"),
                        "uid": ref.get("uid"),
                        "controller": bool(ref.get("controller")),
                    }
                    for ref in (metadata.get("ownerReferences") or [])
                ],
                "replicas": (data.get("spec") or {}).get("replicas"),
                "node_name": (data.get("spec") or {}).get("nodeName"),
                "provider_id": (data.get("spec") or {}).get("providerID"),
                "addresses": [
                    dict(address)
                    for address in ((data.get("status") or {}).get("addresses") or [])
                ],
                "phase": (data.get("status") or {}).get("phase"),
            }
            statement = f"{kind} {cluster_id}/{namespace or '-'}/{name} uid={attributes['uid']}"
            details = []
            if attributes["node_name"]:
                details.append(f"spec.nodeName={attributes['node_name']}")
            if attributes["provider_id"]:
                details.append(f"spec.providerID={attributes['provider_id']}")
            if attributes["phase"]:
                details.append(f"status.phase={attributes['phase']}")
            if details:
                statement += " " + " ".join(details)
            self._merge(
                entity_id,
                entity_kind,
                tenant,
                environment,
                {
                    "tenant_id": tenant,
                    "cluster_id": cluster_id,
                    "namespace": namespace,
                    "environment": environment,
                    "account_id": collection.scope.get("account_id"),
                    "region": collection.scope.get("region"),
                },
                attributes,
                self.evidence(record, statement, environment),
                record,
            )
            self.graph.by_k8s_name[
                f"{tenant}#{cluster_id}#{kind}#{namespace or '-'}#{name}"
            ] = entity_id
            if attributes["uid"]:
                self.graph.by_k8s_uid[f"{tenant}#{cluster_id}#{attributes['uid']}"] = entity_id

        self.link_kubernetes()

    def link_kubernetes(self) -> None:
        linkable = {
            EntityKind.K8S_REPLICASET,
            EntityKind.K8S_POD,
            EntityKind.K8S_NODE,
        }
        for entity in sorted(self.graph.entities.values(), key=lambda e: e.entity_id):
            if entity.kind not in linkable:
                continue
            scope = entity.scope
            tenant = entity.tenant_id
            cluster_id = scope["cluster_id"]
            environment = entity.environment
            for ref in entity.attributes.get("owner_references", []):
                self._link_owner(entity, ref, tenant, cluster_id, environment)
            if entity.kind is EntityKind.K8S_POD:
                self._link_pod_to_node(entity, tenant, cluster_id, environment)
            if entity.kind is EntityKind.K8S_NODE:
                self._link_node_to_instance(entity, tenant, cluster_id, environment)

    def _link_owner(
        self, child: Entity, ref: dict[str, Any], tenant: str, cluster_id: str, environment: str
    ) -> None:
        if not ref.get("controller"):
            return
        uid_key = f"{tenant}#{cluster_id}#{ref['uid']}"
        target_id = self.graph.by_k8s_uid.get(uid_key)
        evidence = list(child.evidence[-1:])
        if target_id is not None:
            self.graph.add_edge(
                Edge(
                    kind=EdgeKind.CONTROLLED_BY,
                    src_id=child.entity_id,
                    dst_id=target_id,
                    basis=f"metadata.ownerReferences[controller].uid == {ref['uid']}",
                    tenant_id=tenant,
                    environment=environment,
                    evidence=evidence,
                )
            )
            return
        name_key = f"{tenant}#{cluster_id}#{ref['kind']}#{child.scope['namespace'] or '-'}#{ref['name']}"
        named_id = self.graph.by_k8s_name.get(name_key)
        reason = (
            f"ownerReference to {ref['kind']}/{ref['name']} names an object that is not in the "
            f"supplied collection for cluster {cluster_id}"
        )
        if named_id is not None:
            reason += (
                f"; a same-named object exists with uid "
                f"{self.graph.entities[named_id].attributes['uid']}, but display names are "
                "reusable so the UID disagreement is not resolved by name matching"
            )
        self.graph.add_unresolved(
            UnresolvedLink(
                kind=EdgeKind.CONTROLLED_BY,
                from_id=child.entity_id,
                target=f"{ref['kind']}/{ref['name']}",
                tenant_id=tenant,
                environment=environment,
                state=LinkState.UNRESOLVED,
                reason=reason,
                candidates=[named_id] if named_id else [],
                evidence=evidence,
                resolving_evidence="the controlling object's own record (uid + name) in a "
                "collection covering this namespace, or a controller revision history.",
            )
        )
        self.add_issue(
            "unresolved_link", child.entity_id, "owner reference could not be resolved", reason,
            "the controlling object record with the referenced uid.",
            [e.record_ref for e in evidence],
        )

    def _link_pod_to_node(self, pod: Entity, tenant: str, cluster_id: str, environment: str) -> None:
        node_name = pod.attributes.get("node_name")
        evidence = list(pod.evidence[-1:])
        if not node_name:
            return
        target_id = self.graph.by_k8s_name.get(
            f"{tenant}#{cluster_id}#Node#-#{node_name}"
        )
        if target_id is not None:
            self.graph.add_edge(
                Edge(
                    kind=EdgeKind.SCHEDULED_ON,
                    src_id=pod.entity_id,
                    dst_id=target_id,
                    basis=f"spec.nodeName={node_name} within cluster {cluster_id}",
                    tenant_id=tenant,
                    environment=environment,
                    evidence=evidence,
                )
            )
            return
        state = self.k8s_scope_covers(tenant, environment, cluster_id, "Node")
        self.graph.add_unresolved(
            UnresolvedLink(
                kind=EdgeKind.SCHEDULED_ON,
                from_id=pod.entity_id,
                target=f"Node/{node_name}",
                tenant_id=tenant,
                environment=environment,
                state=LinkState.NOT_IN_SUPPLIED_SCOPE
                if state == "complete"
                else LinkState.SCOPE_UNAVAILABLE,
                reason=(
                    f"pod schedules onto Node/{node_name} but no such Node object is supplied "
                    f"for cluster {cluster_id} (node coverage: {state})"
                ),
                evidence=evidence,
                resolving_evidence="a Node collection for this cluster, which is cluster-scoped "
                "and therefore not bounded by the namespace filter.",
            )
        )

    def _link_node_to_instance(self, node: Entity, tenant: str, cluster_id: str, environment: str) -> None:
        provider_id = node.attributes.get("provider_id")
        evidence = list(node.evidence[-1:])
        account_id = node.scope.get("account_id")
        region = node.scope.get("region")
        if not provider_id:
            candidates = sorted(
                entity.entity_id
                for entity in self.graph.entities.values()
                if entity.kind is EntityKind.CLOUD_INSTANCE
                and entity.tenant_id == tenant
                and entity.environment == environment
                and node.attributes["addresses"]
                and any(
                    address.get("type") == "InternalIP"
                    and address.get("address") == entity.attributes.get("private_ip")
                    for address in node.attributes["addresses"]
                )
            )
            self.graph.add_unresolved(
                UnresolvedLink(
                    kind=EdgeKind.HOSTS,
                    from_id=node.entity_id,
                    target="cloud instance",
                    tenant_id=tenant,
                    environment=environment,
                    state=LinkState.AMBIGUOUS
                    if len(candidates) > 1
                    else LinkState.UNRESOLVED,
                    reason=(
                        "spec.providerID is absent. An omitted provider reference is not an "
                        "empty instance identifier, and the InternalIP is a network address "
                        "rather than a provider identifier"
                    ),
                    candidates=candidates,
                    evidence=evidence,
                    resolving_evidence=(
                        "the Node's spec.providerID, or an EC2 tag/ownership record binding "
                        "this instance to the cluster node identity"
                    ),
                )
            )
            described = ", ".join(candidates) if candidates else "none"
            self.add_issue(
                "unresolved_link",
                node.entity_id,
                "Node-to-instance link cannot be established",
                (
                    f"Node {node.attributes['name']} has no spec.providerID. Its InternalIP "
                    f"matches {len(candidates)} instance(s) in this tenant and environment "
                    f"({described}); an IP address is a network address, not a provider "
                    "identifier, so no link is asserted and the candidates are reported only."
                ),
                "spec.providerID on the Node, or a provider-side tag linking the instance to "
                "the cluster node.",
                [e.record_ref for e in evidence],
            )
            return
        instance_id = _parse_provider_id(provider_id)
        if instance_id is None:
            self.add_issue(
                "unresolved_link", node.entity_id, "unparseable providerID",
                f"providerID {provider_id!r} does not match aws:///<az>/<instance-id>.",
                "a provider reference in the documented format.",
                [e.record_ref for e in evidence],
            )
            return
        target_id = self.graph.by_instance_key.get(
            f"{tenant}#{account_id}#{region}#{instance_id}"
        )
        basis = (
            f"spec.providerID {provider_id} resolved against cluster account "
            f"{account_id} and region {region} from the manifest"
        )
        if target_id is not None:
            self.graph.add_edge(
                Edge(
                    kind=EdgeKind.HOSTS,
                    src_id=node.entity_id,
                    dst_id=target_id,
                    basis=basis,
                    tenant_id=tenant,
                    environment=environment,
                    evidence=evidence,
                )
            )
            return
        state, coverage_ids = self.aws_scope_covers(tenant, environment, "aws_instance")
        self.graph.add_unresolved(
            UnresolvedLink(
                kind=EdgeKind.HOSTS,
                from_id=node.entity_id,
                target=ec2_arn(str(region), str(account_id), instance_id),
                tenant_id=tenant,
                environment=environment,
                state=LinkState.NOT_IN_SUPPLIED_SCOPE
                if state == "complete"
                else LinkState.SCOPE_UNAVAILABLE,
                reason=(
                    f"providerID names instance {instance_id}, which does not appear in the "
                    f"supplied cloud inventory (coverage: {state}; "
                    f"collections: {', '.join(coverage_ids) or 'none'})"
                ),
                evidence=evidence,
                resolving_evidence="a cloud inventory observation covering this instance id in "
                "the cluster's account and region.",
            )
        )

    # -- catalog ---------------------------------------------------------

    def resolve_catalog(self) -> None:
        for record in sorted(self.inputs.catalog_rows, key=lambda r: r.record_ref):
            collection = record.collection
            row = record.data
            tenant = collection.tenant_id
            environment = row["environment"]
            service_id = row["service_id"]
            entity_id = f"cat:{tenant}:{service_id}:{environment}"
            attributes = {
                "service_id": service_id,
                "service_name": row["service_name"],
                "environment": environment,
                "application_team": row["owner_team"],
                "cluster_id": row["cluster_id"],
                "namespace": row["namespace"],
                "deployment_name": row["deployment_name"],
                "declared_dependency_arn": row["declared_dependency_arn"],
            }
            statement = (
                f"service_id={service_id} service_name={row['service_name']} "
                f"environment={environment} owner_team={row['owner_team']} "
                f"workload={row['cluster_id']}/{row['namespace']}/{row['deployment_name']} "
                f"declared_dependency_arn={row['declared_dependency_arn']}"
            )
            self._merge(
                entity_id,
                EntityKind.CATALOG_APPLICATION,
                tenant,
                environment,
                {"tenant_id": tenant, "environment": environment},
                attributes,
                self.evidence(record, statement, environment),
                record,
            )
            self.link_catalog(record, entity_id, attributes, tenant, environment)

    def link_catalog(
        self,
        record: RawRecord,
        app_id: str,
        attributes: dict[str, Any],
        tenant: str,
        environment: str,
    ) -> None:
        evidence = [self.evidence(record, f"catalog workload reference for {app_id}", environment)]
        cluster_id = attributes["cluster_id"]
        namespace = attributes["namespace"]
        deployment_name = attributes["deployment_name"]
        if deployment_name:
            target_id = self.graph.by_k8s_name.get(
                f"{tenant}#{cluster_id}#Deployment#{namespace}#{deployment_name}"
            )
            if target_id is not None:
                self.graph.add_edge(
                    Edge(
                        kind=EdgeKind.RUNS_WORKLOAD,
                        src_id=app_id,
                        dst_id=target_id,
                        basis=(
                            "catalog (cluster_id, namespace, deployment_name) == Kubernetes "
                            "Deployment name, same tenant and cluster"
                        ),
                        tenant_id=tenant,
                        environment=environment,
                        evidence=evidence,
                    )
                )
            else:
                coverage = self.k8s_scope_covers(tenant, environment, str(cluster_id), "Deployment")
                self.graph.add_unresolved(
                    UnresolvedLink(
                        kind=EdgeKind.RUNS_WORKLOAD,
                        from_id=app_id,
                        target=f"{cluster_id}/{namespace}/{deployment_name}",
                        tenant_id=tenant,
                        environment=environment,
                        state=LinkState.NOT_IN_SUPPLIED_SCOPE
                        if coverage == "complete"
                        else LinkState.SCOPE_UNAVAILABLE,
                        reason=(
                            f"no Deployment named {deployment_name} exists in "
                            f"{cluster_id}/{namespace} among the supplied records "
                            f"(deployment coverage for that cluster: {coverage})"
                        ),
                        candidates=[],
                        evidence=evidence,
                        resolving_evidence=(
                            "a Deployment record with that name, or a corrected workload "
                            "reference in the catalog"
                        ),
                    )
                )
                self.add_issue(
                    "unresolved_link",
                    app_id,
                    "catalog workload reference does not resolve",
                    f"catalog row {record.record_ref} points at "
                    f"{cluster_id}/{namespace}/{deployment_name}; coverage={coverage}.",
                    "the Deployment object itself, or a corrected catalog reference.",
                    [record.record_ref],
                )

        arn = attributes["declared_dependency_arn"]
        if arn:
            dependency_evidence = [
                self.evidence(record, f"catalog declared_dependency_arn={arn}", environment)
            ]
            target_id = self.graph.by_arn.get(f"{tenant}#{arn}")
            target = self.graph.entities.get(target_id) if target_id else None
            if target is not None and target.environment == environment:
                self.graph.add_edge(
                    Edge(
                        kind=EdgeKind.DECLARES_DEPENDENCY,
                        src_id=app_id,
                        dst_id=target.entity_id,
                        basis="catalog declared_dependency_arn == provider ARN within the same tenant",
                        tenant_id=tenant,
                        environment=environment,
                        evidence=dependency_evidence,
                    )
                )
            elif target is not None:
                self.graph.add_unresolved(
                    UnresolvedLink(
                        kind=EdgeKind.DECLARES_DEPENDENCY,
                        from_id=app_id,
                        target=arn,
                        tenant_id=tenant,
                        environment=environment,
                        state=LinkState.UNRESOLVED,
                        reason=(
                            f"{arn} resolves inside this tenant but only to a resource classified "
                            f"in environment {target.environment!r}, not {environment!r}; the "
                            "collection scope is authoritative for environment"
                        ),
                        candidates=[target.entity_id],
                        evidence=dependency_evidence,
                        resolving_evidence="a catalog statement naming the environment of the "
                        "dependency, or a state/ownership record that classifies this ARN.",
                    )
                )
                self.add_issue(
                    "environment_mismatch", app_id,
                    "declared dependency resolves to another environment",
                    f"catalog row {record.record_ref} declares {arn}, observed as "
                    f"{target.environment}.", "an environment-qualified dependency statement.",
                    [record.record_ref],
                )
            else:
                resource_type = "aws_db_instance" if ":db:" in arn else "aws_instance"
                state, coverage_ids = self.aws_scope_covers(tenant, environment, resource_type)
                other_tenants = sorted(
                    {
                        key.split("#", 1)[0]
                        for key, entity_id in self.graph.by_arn.items()
                        if key.endswith(f"#{arn}")
                        and self.graph.entities[entity_id].tenant_id != tenant
                    }
                )
                observed_elsewhere = (
                    " It is observed under tenant(s) "
                    + ", ".join(other_tenants)
                    + ", whose collections are not usable here."
                    if other_tenants
                    else ""
                )
                self.graph.add_unresolved(
                    UnresolvedLink(
                        kind=EdgeKind.DECLARES_DEPENDENCY,
                        from_id=app_id,
                        target=arn,
                        tenant_id=tenant,
                        environment=environment,
                        state=LinkState.SCOPE_UNAVAILABLE,
                        reason=(
                            f"{arn} is not observed in any collection belonging to tenant "
                            f"{tenant} (coverage: {state}); an ARN seen only in another "
                            "tenant's collections is not evidence for this tenant"
                        ),
                        evidence=dependency_evidence,
                        resolving_evidence=(
                            "a cloud inventory or state collection for this tenant whose scope "
                            f"includes {resource_type} in the ARN's account and region"
                        ),
                    )
                )
                self.add_issue(
                    "tenant_scope",
                    app_id,
                    "declared dependency is outside this tenant's supplied evidence",
                    (
                        f"catalog row {record.record_ref} (tenant {tenant}) declares dependency "
                        f"{arn}, which no collection of this tenant reports; its resource types "
                        f"for this environment are {coverage_ids or 'not supplied'}."
                        + observed_elsewhere
                    ),
                    "a tenancy/ownership ledger, or an inventory collection for this tenant "
                    f"whose resource_types include {resource_type}.",
                    [record.record_ref],
                )

    # -- shared merge + collection-level limitations ---------------------

    def _merge(
        self,
        entity_id: str,
        kind: EntityKind,
        tenant: str,
        environment: str,
        scope: dict[str, Any],
        attributes: dict[str, Any],
        evidence: Evidence,
        record: RawRecord,
    ) -> Entity:
        existing = self.graph.entities.get(entity_id)
        if existing is None:
            entity = Entity(
                entity_id=entity_id,
                kind=kind,
                tenant_id=tenant,
                environment=environment,
                scope=scope,
                attributes=dict(attributes),
            )
            entity.add_evidence(evidence)
            self.graph.add_entity(entity)
            return self.graph.entities[entity_id]
        for key, value in attributes.items():
            current = existing.attributes.get(key)
            if value is None:
                continue
            if current is not None and current != value and key != "evidence":
                self.graph.add_conflict(
                    Conflict(
                        subject_id=entity_id,
                        attribute=key,
                        statements=[e for e in existing.evidence[-1:]] + [evidence],
                        note=(
                            f"two collections in the same scope disagree on {key!r}: "
                            f"{current!r} vs {value!r}"
                        ),
                    )
                )
            else:
                existing.attributes[key] = value
        existing.add_evidence(evidence)
        return existing

    def report_collection_limits(self) -> None:
        for collection in sorted(
            self.inputs.manifest.collections.values(), key=lambda c: c.snapshot_id
        ):
            refs = []
            if collection.payload_path:
                refs = [
                    record.record_ref
                    for record in (
                        self.inputs.terraform_resources
                        + self.inputs.aws_instances
                        + self.inputs.aws_databases
                        + self.inputs.k8s_objects
                        + self.inputs.catalog_rows
                    )
                    if record.collection.snapshot_id == collection.snapshot_id
                ][:1]
            if not collection.available:
                self.add_issue(
                    "unavailable_evidence",
                    collection.snapshot_id,
                    f"{collection.source_family.value} collection was not provided",
                    (
                        f"{collection.snapshot_id} (tenant {collection.tenant_id}, "
                        f"workspace/cluster {collection.scope.get('workspace_id') or collection.scope.get('cluster_id')}) "
                        "has status=not_provided and coverage=unknown with no timestamps. "
                        "This is not an empty inventory: questions about this source family "
                        "for this tenant and environment are answered 'unavailable'."
                    ),
                    f"the {collection.source_family.value} payload for this scope, plus its "
                    "observation time and coverage declaration.",
                    [],
                )
                continue
            freshness = collection.freshness(self.inputs.as_of)
            if freshness == "stale":
                positive = [e.record_ref for e in self.graph.all_evidence()
                            if e.snapshot_id == collection.snapshot_id][:3]
                self.add_issue(
                    "freshness",
                    collection.snapshot_id,
                    f"observations in {collection.source_family.value} collection are stale",
                    (
                        self.inputs.manifest.collections[collection.snapshot_id]
                        .describe_freshness(self.inputs.as_of)
                        + f". Every claim sourced only from this collection is "
                        f"{collection.age_seconds(self.inputs.as_of)}s older than the "
                        "evaluation time and cannot establish the current state."
                    ),
                    "a refreshed collection for the same scope with a newer observed_at.",
                    positive or refs,
                )
            if not collection.complete:
                self.add_issue(
                    "coverage",
                    collection.snapshot_id,
                    "collection coverage is not complete",
                    f"{collection.snapshot_id} declares coverage={collection.coverage}.",
                    "a collector declaration of completeness for this scope.",
                    refs,
                )
            scope = collection.scope
            if "instance_ids" in scope:
                self.add_issue(
                    "coverage",
                    collection.snapshot_id,
                    "inventory is complete only inside an explicit id filter",
                    (
                        f"{collection.snapshot_id} is complete within scope "
                        f"instance_ids={scope['instance_ids']} and resource_types="
                        f"{scope.get('resource_types')}; it supports no claim about objects "
                        "outside that filter, and its empty databases array is a scope "
                        "statement rather than an absence claim."
                    ),
                    "an unfiltered collection for this account and environment.",
                    refs,
                )

    def report_similarity_traps(self) -> None:
        """Record the similarities this model refused to treat as identity."""
        by_name: dict[tuple, list[Entity]] = {}
        by_ip: dict[tuple, list[Entity]] = {}
        by_identifier: dict[tuple, list[Entity]] = {}
        for entity in self.graph.entities.values():
            if entity.kind is EntityKind.CLOUD_INSTANCE:
                key = (entity.tenant_id, entity.environment)
                name = entity.attributes.get("display_name")
                ip = entity.attributes.get("private_ip")
                if name:
                    by_name.setdefault((name,) + key, []).append(entity)
                if ip:
                    by_ip.setdefault((ip,) + key, []).append(entity)
            elif entity.kind is EntityKind.CLOUD_DATABASE:
                identifier = entity.attributes.get("db_instance_identifier")
                if identifier:
                    by_identifier.setdefault(identifier, []).append(entity)

        for label, groups in (
            ("tags.Name", by_name),
            ("PrivateIpAddress", by_ip),
            ("DBInstanceIdentifier", by_identifier),
        ):
            for key, entities in sorted(groups.items(), key=lambda item: str(item[0])):
                if len(entities) < 2:
                    continue
                ids = sorted(entity.entity_id for entity in entities)
                refs = sorted(
                    evidence.record_ref for entity in entities for evidence in entity.evidence
                )
                self.add_issue(
                    "ambiguous_similarity",
                    str(key),
                    f"{len(entities)} distinct resources share {label}={key[0]!r}",
                    (
                        f"Resources {', '.join(ids)} all carry {label}={key[0]!r} but differ on "
                        "their scoped identity key, so they are kept as separate entities and "
                        "no relationship is inferred from the shared value."
                    ),
                    "nothing further is needed to keep them separate; a provider identifier "
                    "(ARN) is already the join key. Only an authoritative ownership record "
                    "could justify treating them as one.",
                    refs,
                )

    def run(self) -> "ResolvedResult":
        self.resolve_cloud()
        self.resolve_terraform()
        self.resolve_kubernetes()
        self.resolve_catalog()
        self.report_similarity_traps()
        self.report_collection_limits()
        return ResolvedResult(graph=self.graph, issues=self.issues)


@dataclass
class ResolvedResult:
    graph: ContextGraph
    issues: list[Issue]


def _available(graph: ContextGraph, scope: QueryScope, family: SourceFamily) -> list[Collection]:
    return [
        collection
        for collection in graph.collections_in(scope, family.value)
        if collection.available
    ]


def cloud_scope_covers(
    graph: ContextGraph,
    scope: QueryScope,
    as_of: datetime,
    environment: str,
    resource_type: str,
) -> tuple[str, list[str]]:
    """What the supplied cloud inventory can say about one resource type.

    ``complete`` lets absence be reported as ``not_found_in_supplied_scope``;
    ``unavailable`` means only that no claim is possible.
    """
    matching = [
        collection
        for collection in _available(graph, scope, SourceFamily.AWS)
        if resource_type in collection.scope.get("resource_types", [])
    ]
    if not matching:
        return "unavailable", []
    ids = sorted(collection.snapshot_id for collection in matching)
    if all(collection.complete for collection in matching):
        return "complete", ids
    return "unknown", ids


def terraform_scope_covers(
    graph: ContextGraph,
    scope: QueryScope,
    as_of: datetime,
    environment: str,
    resource_type: str,
) -> tuple[str, list[str]]:
    """State evidence coverage, with staleness folded into the state name.

    ``complete_stale`` keeps absence meaningful but bounds it to an observation
    beyond its freshness budget.
    """
    matching = [
        collection
        for collection in _available(graph, scope, SourceFamily.TERRAFORM)
        if resource_type in collection.scope.get("resource_types", [])
    ]
    if not matching:
        return "unavailable", []
    ids = sorted(collection.snapshot_id for collection in matching)
    if not all(collection.complete for collection in matching):
        return "unknown", ids
    stale = any(collection.freshness(as_of) == "stale" for collection in matching)
    return ("complete_stale" if stale else "complete"), ids


def k8s_scope_covers(
    graph: ContextGraph, scope: QueryScope, cluster_id: str, kind: str
) -> str:
    for collection in graph.collections_in(scope, SourceFamily.KUBERNETES.value):
        if not collection.available or collection.scope.get("cluster_id") != cluster_id:
            continue
        if kind not in collection.scope.get("kinds", []):
            return "out_of_scope"
        return "complete" if collection.complete else "unknown"
    return "unavailable"


def k8s_key(tenant: str, cluster_id: str, kind: str, namespace: str | None, name: str) -> str:
    return f"k8s:{tenant}:{cluster_id}:{kind}:{namespace or '-'}:{name}"


def _parse_provider_id(provider_id: str) -> str | None:
    """aws:///<availability-zone>/<instance-id>; the reference carries no account."""
    if not provider_id.startswith("aws:///"):
        return None
    parts = provider_id[len("aws://"):].strip("/").split("/")
    if len(parts) != 2 or not parts[1]:
        return None
    return parts[1]


def _fmt_tags(tags: dict[str, str]) -> str:
    return "{" + ", ".join(f"{key}={tags[key]}" for key in sorted(tags)) + "}"
