"""Executable checks of the decisions that matter.

Run:  python3 -m unittest discover -s tests -v

Each test states the implementation error it would catch. Several build from a
modified copy of the supplied inputs, because the cheapest way to prove a rule is
honoured is to supply a record that tempts the code to break it.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from context_layer.answers import answer_application_context, answer_terraform_management
from context_layer.build import build, documents, dump
from context_layer.ingest import load_inputs, load_manifest
from context_layer.model import EdgeKind, EntityKind, EvidenceStatus, LinkState
from context_layer.resolve import Resolver
from context_layer.store import ContextGraph, QueryScope, TenantLeakError

ROOT = Path(__file__).resolve().parents[1]
INPUT_FILES = [
    "manifest.json",
    "aws_inventory.json",
    "k8s_resources.json",
    "service_catalog.csv",
    "terraform_state/acme-production.json",
    "terraform_state/acme-staging.json",
]


def staged(mutate=None) -> tuple[Path, ContextGraph, object]:
    """Build the pipeline from a copy of the inputs, optionally edited first."""
    tmp = Path(tempfile.mkdtemp())
    for relative in INPUT_FILES:
        destination = tmp / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    if mutate is not None:
        mutate(tmp)
    manifest = load_manifest(tmp)
    inputs = load_inputs(tmp, manifest)
    result = Resolver(inputs).run()
    return tmp, result.graph, inputs.as_of


def loaded() -> tuple[ContextGraph, object]:
    manifest = load_manifest(ROOT)
    inputs = load_inputs(ROOT, manifest)
    result = Resolver(inputs).run()
    return result.graph, inputs.as_of


GRAPH, AS_OF = loaded()
PROD = QueryScope("acme", "prod", "acme production")
BRAVO = QueryScope("bravo", "prod", "bravo production")


def answer_a(graph: ContextGraph, scope: QueryScope, as_of) -> dict:
    return answer_terraform_management(graph, scope, as_of, scope.environment)


def results_by_instance(payload: dict) -> dict[str, dict]:
    return {row["instance_id"]: row for row in payload["results"]}


def binding_of(payload: dict, instance_id: str) -> dict:
    return results_by_instance(payload)[instance_id]["managed_binding"]


class JustifiedMatches(unittest.TestCase):
    """A real cross-source match, proven through to a substantive answer."""

    def test_catalog_to_cloud_path_is_supported_by_stated_keys(self) -> None:
        graph, as_of = GRAPH, AS_OF
        answer = answer_application_context(graph, PROD, as_of, "payments-api")
        result = answer["results"][0]
        path = result["workload_path"]

        self.assertEqual(
            path["cloud_resources_reached"],
            [
                "aws:ec2:acme:111111111111:us-east-1:i-00000000000000101",
                "aws:ec2:acme:111111111111:us-east-1:i-00000000000000102",
            ],
        )
        kinds = [hop["kind"] for hop in path["hops"]]
        for required in ("runs_workload", "controlled_by", "scheduled_on", "hosts"):
            self.assertIn(required, kinds)

        hosts = [hop for hop in path["hops"] if hop["kind"] == "hosts"]
        self.assertTrue(
            all("providerID" in hop["basis"] for hop in hosts),
            "a Node-to-instance link must be justified by the provider reference the "
            "source states, never by the node name or IP",
        )
        ownership = [hop for hop in path["hops"] if hop["kind"] == "controlled_by"]
        self.assertTrue(all("uid" in hop["basis"] for hop in ownership))

        dependency = result["declared_dependencies"][0]
        self.assertEqual(dependency["status"], EvidenceStatus.FOUND.value)
        self.assertEqual(
            dependency["target_entity_id"],
            "aws:rds:acme:arn:aws:rds:us-east-1:111111111111:db:payments-db",
        )
        self.assertEqual(
            result["application"]["application_team"]["value"], "team-payments"
        )
        teams = result["responsibility"]["infrastructure_operator"]["distinct_teams"]
        self.assertEqual(teams, ["team-legacy-platform", "team-platform"])

    # Catches: an off-by-one in traversal direction, or matching Node to instance by
    # InternalIP, which would silently reach the wrong instance and still "work".


class MisleadingSimilarity(unittest.TestCase):
    """Lookalikes stay separate, and one tenant cannot borrow another's evidence."""

    def test_shared_name_and_ip_do_not_merge_two_instances(self) -> None:
        entities = {
            entity.entity_id: entity
            for entity in GRAPH.entities_in(PROD, [EntityKind.CLOUD_INSTANCE])
            if entity.attributes.get("display_name") == "batch-runner"
        }
        self.assertEqual(len(entities), 2)
        first, second = sorted(entities)
        self.assertEqual(
            entities[first].attributes["private_ip"],
            entities[second].attributes["private_ip"],
            "the test is only meaningful while these two share an IP address",
        )
        self.assertNotEqual(
            entities[first].attributes["vpc_id"], entities[second].attributes["vpc_id"]
        )
        self.assertNotEqual(entities[first].attributes["arn"], entities[second].attributes["arn"])

        # Neither may inherit the other's Terraform binding, and neither is bound.
        for entity_id in (first, second):
            self.assertEqual(GRAPH.edges_to(PROD, entity_id, [EdgeKind.MANAGED_BINDING]), [])

    def test_same_database_identifier_in_two_accounts_stays_two_entities(self) -> None:
        databases = GRAPH.entities_in(
            QueryScope("acme"), [EntityKind.CLOUD_DATABASE]
        )
        identifiers = [entity.attributes["db_instance_identifier"] for entity in databases]
        self.assertEqual(identifiers, ["payments-db", "payments-db"])
        self.assertEqual(len({entity.entity_id for entity in databases}), 2)

    def test_another_tenant_cannot_claim_this_tenants_workload(self) -> None:
        def tamper(root: Path) -> None:
            csv_path = root / "service_catalog.csv"
            text = csv_path.read_text(encoding="utf-8")
            # Make bravo's payments-api point directly at acme's production Deployment.
            tampered = text.replace(
                "catalog-bravo-20260916T114500Z,svc-payments-prod,payments-api,prod,"
                "team-bravo-apps,bravo-prod,production,payments-api,",
                "catalog-bravo-20260916T114500Z,svc-payments-prod,payments-api,prod,"
                "team-bravo-apps,acme-prod,production,payments-api,",
            )
            self.assertNotEqual(text, tampered, "the fixture row moved; update this test")
            csv_path.write_text(tampered, encoding="utf-8")

        root, graph, as_of = staged(tamper)
        bravo = answer_application_context(graph, BRAVO, as_of, "payments-api")
        serialised = dump(bravo)
        for forbidden in (
            "k8s:acme:", "aws:ec2:acme:", "aws:rds:acme:", "tf:acme:",
            "catalog-acme", "k8s-acme-prod", "aws-acme-prod", "tf-acme-prod",
        ):
            self.assertNotIn(
                forbidden, serialised,
                "a cross-tenant workload reference must not pull another tenant's objects "
                "or records into this tenant's answer and evidence",
            )
        result = bravo["results"][0]
        self.assertEqual(result["workload_path"]["hops"], [])
        self.assertEqual(
            [link.state.value for link in graph.unresolved_from(BRAVO,
             "cat:bravo:svc-payments-prod:prod")].count("scope_unavailable"),
            2,
        )
        acme = answer_application_context(graph, PROD, as_of, "payments-api")
        self.assertEqual(
            acme["results"][0]["workload_path"]["cloud_resources_reached"],
            [
                "aws:ec2:acme:111111111111:us-east-1:i-00000000000000101",
                "aws:ec2:acme:111111111111:us-east-1:i-00000000000000102",
            ],
            "the other tenant's tampered reference must not disturb this tenant's answer",
        )
        # Catches: resolving by name or ARN without a tenant prefix on the index key.

    def test_query_scope_guard_rejects_foreign_evidence(self) -> None:
        foreign = next(
            evidence
            for evidence in GRAPH.all_evidence()
            if evidence.tenant_id == "bravo"
        )
        with self.assertRaises(TenantLeakError):
            GRAPH.check_evidence(PROD, [foreign])

    def test_undeclared_tenant_is_rejected_rather_than_answered_as_empty(self) -> None:
        """Catches a query layer that silently returns nothing for a mistyped tenant."""
        with self.assertRaises(ValueError):
            build(ROOT, tenant_id="acme-prod")
        bravo = build(ROOT, tenant_id="bravo").answers["A"]
        self.assertEqual(bravo["query_scope"]["tenant_id"], "bravo")
        self.assertEqual(bravo["summary"]["instances_observed_running"], 1)


class QualifiedAbsence(unittest.TestCase):
    """mode=data, staleness, unavailable sources and ambiguity keep their qualifiers."""

    def test_data_source_reference_is_not_reported_as_a_managed_binding(self) -> None:
        payload = answer_a(GRAPH, PROD, AS_OF)
        binding = binding_of(payload, "i-00000000000000103")
        self.assertEqual(binding["status"], EvidenceStatus.NOT_FOUND_IN_SUPPLIED_SCOPE.value)
        self.assertEqual(
            [reference["mode"] for reference in binding["data_references"]], ["data"]
        )
        self.assertIn("data-source", binding["why"])

    def test_flipping_the_state_record_to_managed_would_change_the_answer(self) -> None:
        """Proves the code reads `mode`, rather than treating any state record as a binding."""

        def promote(root: Path) -> None:
            path = root / "terraform_state" / "acme-production.json"
            state = json.loads(path.read_text(encoding="utf-8"))
            for resource in state["resources"]:
                if resource["mode"] == "data":
                    resource["mode"] = "managed"
            path.write_text(json.dumps(state), encoding="utf-8")

        root, graph, as_of = staged(promote)
        payload = answer_a(graph, QueryScope("acme", "prod"), as_of)
        self.assertEqual(
            payload["summary"]["managed_binding_found"], 3,
            "promoting the data record should raise the found count by exactly one",
        )
        self.assertNotIn("data_references", binding_of(payload, "i-00000000000000103"))

    def test_stale_state_qualifies_bindings_and_fresh_state_removes_the_qualifier(self) -> None:
        payload = answer_a(GRAPH, PROD, AS_OF)
        found = binding_of(payload, "i-00000000000000101")
        self.assertEqual(found["status"], EvidenceStatus.FOUND.value)
        self.assertEqual(found["bindings"][0]["workspace_id"], "acme-prod-core")
        self.assertEqual(
            found["bindings"][0]["observed_at"], "2026-09-02T09:00:00Z"
        )
        self.assertEqual(found["bindings"][0]["qualifiers"], [
            "state_observed_stale: 2026-09-02T09:00:00Z"
        ])
        self.assertTrue(
            any("14 days older" in line for line in payload["limitations"]),
            "the staleness of the only binding evidence must appear with the results",
        )

        def refresh(root: Path) -> None:
            manifest = root / "manifest.json"
            text = manifest.read_text(encoding="utf-8")
            self.assertIn("2026-09-02T09:00:00Z", text)
            manifest.write_text(
                text.replace("2026-09-02T09:00:00Z", "2026-09-16T11:00:00Z"), encoding="utf-8"
            )

        root, graph, as_of = staged(refresh)
        refreshed = answer_a(graph, PROD, as_of)
        self.assertEqual(
            binding_of(refreshed, "i-00000000000000101")["bindings"][0]["qualifiers"], []
        )
        self.assertFalse(any("14 days older" in line for line in refreshed["limitations"]))

    def test_unavailable_source_is_answered_as_unavailable_not_as_absence(self) -> None:
        payload = answer_a(GRAPH, BRAVO, AS_OF)
        self.assertEqual(payload["summary"]["instances_observed_running"], 1)
        self.assertEqual(
            payload["summary"]["binding_evidence_unavailable"], 1,
            "bravo's Terraform collection was not provided: absence of a binding is not "
            "establishable, and an unavailable collection is not an empty inventory",
        )
        self.assertEqual(payload["summary"]["no_binding_found_in_supplied_scope"], 0)
        self.assertNotIn(
            "acme", dump(payload),
            "bravo shares an AWS account with acme; the answer must not borrow acme records",
        )

    def test_node_without_provider_reference_stops_the_path_with_candidates(self) -> None:
        node_id = "k8s:acme:acme-prod:Node:-:ip-10-0-9-9"
        self.assertEqual(GRAPH.edges_from(PROD, node_id, [EdgeKind.HOSTS]), [])
        links = [
            link for link in GRAPH.unresolved if link.from_id == node_id and link.kind is EdgeKind.HOSTS
        ]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].state, LinkState.AMBIGUOUS)
        self.assertEqual(len(links[0].candidates), 2)
        self.assertIn("providerID", links[0].resolving_evidence)


class RepeatableRebuild(unittest.TestCase):
    """Reprocessing must not duplicate entities or change identities."""

    def test_two_builds_produce_identical_documents_and_one_of_each_relationship(self) -> None:
        first = build(ROOT)
        second = build(ROOT)
        self.assertEqual(dump(documents(first)), dump(documents(second)))

        seen_entities = [entity.entity_id for entity in first.graph.entities.values()]
        self.assertEqual(len(seen_entities), len(set(seen_entities)))
        seen_edges = Counter(
            (edge.kind, edge.src_id, edge.dst_id) for edge in first.graph.edges
        )
        self.assertEqual([key for key, count in seen_edges.items() if count > 1], [])
        self.assertEqual(len(first.graph.edges), 25)

        # Several collections share one payload file; re-reading it must not double the
        # relationships and unresolved links derived from it.
        seen_links = Counter((link.kind, link.from_id, link.target) for link in first.graph.unresolved)
        self.assertEqual([key for key, count in seen_links.items() if count > 1], [])
        self.assertEqual(len(first.graph.unresolved), 5)

    def test_evaluation_time_comes_from_the_manifest_not_the_clock(self) -> None:
        payload = answer_a(GRAPH, PROD, AS_OF)
        self.assertEqual(payload["evaluation_time"], "2026-09-16T12:00:00Z")
        offsets = {
            collection.snapshot_id: collection.freshness(AS_OF)
            for collection in GRAPH.collections_in(QueryScope("acme", "staging"))
        }
        self.assertEqual(
            offsets["k8s-acme-staging-20260916T115300Z"], "fresh",
            "that collection's observed_at is written as -04:00; treating it as UTC would "
            "make it look four hours stale",
        )


if __name__ == "__main__":
    unittest.main()
