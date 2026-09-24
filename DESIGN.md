# Engineering handoff: local context layer

StackGen take-home. Python 3.10+, standard library only.

```bash
python3 tools/check_inputs.py                # verify the input envelope
python3 -m context_layer.build --check       # rebuild; asserts identical output
python3 -m unittest discover -s tests -t .   # 13 checks, one class per required area

# re-ask for another scope (unknown --tenant rejected)
python3 -m context_layer.build --tenant bravo --environment prod
```

Query defaults come from `manifest.query_defaults`. `out/` holds the generated answers,
issues report and model summary.

## Model and design

A typed in-memory property graph, rebuilt from the files on every run. Both
questions are cross-source traversals (catalog -> workload -> node -> instance ->
Terraform record), so a query reads edges instead of re-deriving joins. SQLite
would have buried typed absence in JOINs; the cost is no persistence between runs,
which the brief allows.

Three kinds of thing are stored:

| Stored | Meaning |
|---|---|
| `Entity` | one thing under a scope-qualified identity, holding `Evidence`: record ref, snapshot, observation time, freshness, coverage, asserted attribute |
| `Edge` | a relationship some source's own key justifies, with its basis and qualifiers |
| `UnresolvedLink` / `Conflict` | what the evidence could not join, or where sources disagree |

Unresolved links are deliberately *not* edges, so they cannot be traversed as
facts. Absence is typed three ways: `found`; `not_found_in_supplied_scope` — a
collection declared complete for that scope did not report it; and `unavailable` —
nothing covered that scope.

Rules preserved:

1. An identifier means nothing outside the scope that collected it: every key
   starts with the manifest tenant, then account/region/ARN for cloud resources,
   workspace for state records, cluster and UID for Kubernetes objects, declared
   environment for catalog rows.
2. A relationship exists only when a source states the key that justifies it.
   Shared `tags.Name`, private IPs, labels and bare identifiers produce an issue,
   never an edge.
3. `mode=data` is not management, and an omitted tag or absent provider reference
   is not an empty-string claim.

## Consequential decisions

**Tenant-scoped identity rather than one canonical provider object** (the
alternative: a shared cloud entity per ARN with tenant attachments). I chose
scoped keys because account `111111111111` is reported complete by *two* tenants
for the same `i-...101`; a shared entity would let a bravo query reach acme
evidence. It is enforced structurally: indexes are tenant-prefixed, so a cross-tenant
join cannot form, and emitted evidence is re-checked against the caller's
scope (`TenantLeakError`). Revisit if an authoritative account -> tenancy
ledger shows accounts are legitimately shared.

**Absence derived from collection metadata, not from a missing edge.** The
alternatives: answer only what sources affirm (safe, near useless), or say
"unmanaged" (what a naive join yields). Instead a negative is licensed only by a
collection declared complete for that resource type, and qualified when stale. If
collectors report partial coverage, or a workspace list proves non-exhaustive,
negatives weaken to `unavailable`.

## Verification

Assumption I checked: no relationship rests on a display name, IP address or bare
identifier. I tested it on the tempting cases, two built by mutating copies of
the inputs. The `batch-runner` pair (`i-...104`/`i-...105`) share a name
*and* a private IP yet differ by VPC and ARN; `payments-db` is one identifier
across two accounts; and a tampered catalog row making bravo claim acme's
production Deployment forms zero edges, leaves bravo's path empty, and changes
nothing for acme.

What it caught: a real bug. Three collections share `aws_inventory.json` and two
share `service_catalog.csv`, and I read each payload once per collection, so every
catalog-derived edge and unresolved link was duplicated. The loader now reads a
file once and `add_edge`, `add_unresolved` and `add_evidence` are idempotent,
making duplication structurally impossible. The ARN-based binding join is unchanged.

## Readiness and next steps

A read-only consumer may rely on: which instances a collection observed running
in production for one tenant; which of those have a managed binding **in the
supplied state**, with workspace, address and observation time; the substantiated
`payments-api` path to `i-...101`/`i-...102` and its declared database dependency;
and the issues report, which names the evidence that would resolve each link.

They must not rely on: how management looks *now*. Every production Terraform
claim comes from one snapshot 14 days past its freshness budget, so
`i-...104`/`i-...105` cannot be distinguished between deleted, never-managed, and
managed in a workspace that was not supplied. The same gap leaves the
`operator_team` tag disagreement and the two-tenant claim on `i-...101` unresolved.

Next: (1) model account -> tenancy as an input, so the shared-instance
collision becomes a resolvable claim rather than a permanent issue; (2) lift the
typed-absence rules into a declared policy per source family, so "what may a
negative claim rest on?" has one auditable answer as collectors are added.

## Time and unfinished work

Roughly: 25m reading inputs and noting identity traps; 85m model, ingest and
resolver; 35m answers and issues; 45m tests (found the duplicate-payload bug);
25m this note and cleanup; 20m reruns — ≈4h.

Unfinished: one tenant/environment scope per run, so no cross-tenant report; no
payload schema validation beyond the supplied envelope check; no fixture for a pod
referencing an absent Node, because no supplied pod does; `out/` is written whole
rather than per-tenant. Historical and incremental processing are omitted, as
allowed.
