# MHBench+ generation contract

## Purpose and boundary

MHBench+ is the deterministic **range-skeleton generator/compiler** in the
East Quay workflow. It resolves reviewed inputs into deployable services,
networks, Compose configuration, service build contexts, and (when permitted)
a Harbor task package. It does not need an LLM at runtime and does not discover
vulnerabilities or infer a trustworthy attack chain from network topology.

The optional LLM step happens **after** a skeleton exists. It can propose
edits that make the Harbor case and business narrative more coherent. Its
output is untrusted until a human approves it and the deterministic gates pass.
The response contract and safety constraints are in
[`llm-harbor-case-refinement.md`](llm-harbor-case-refinement.md).

```text
Human-authored scenario + reviewed service/weakness inputs
                           |
                           v
             MHBench+ deterministic compiler
                           |
                           v
       Range skeleton: Compose + build contexts + evidence hooks
                           |
                           v
        Optional LLM case refinement (proposal only)
                           |
                  human approval
                           |
                           v
          deterministic validation and Harbor packaging
```

## Current implemented inputs

East Quay uses scenario/range schema **1.1** for explicit system interactions,
deployed-weakness-to-workflow mapping, and the CVE-inspired analog provenance
track. Legacy 1.0 pairs remain valid when they do not use those 1.1 features,
and the pair's schema versions must match.

| Input | Contract | East Quay file |
|---|---|---|
| Business semantics | Departments, actors, business systems, normal workflows, records, and explicit system interactions distinguishing service integrations from human handoffs. No vulnerability claims. | `examples/scenarios/east-quay-terminal/scenario.yaml` |
| Concrete range plan | Explicit entry state, service instances, network attachments, service flows, resource goals, weakness candidates, and any authored candidate-path hypotheses. Candidate presence does **not** select or deploy it. | `examples/scenarios/east-quay-terminal/range-plan.yaml` |
| Service catalog | Reviewed image pins or build-context/Dockerfile references and service runtime defaults. | `examples/scenarios/east-quay-terminal/service-catalog.yaml` |
| Weakness catalog | Reviewed deployment templates for explicitly selected weakness instances. Required if `weaknesses` is non-empty. | Not yet populated for East Quay |
| Harbor task assets | Authored task metadata, README, verifier, optional hints, and solution material. | `examples/scenarios/east-quay-terminal/harbor-assets/` |

All security-relevant selection is explicit. In particular:

- MHBench+ must not randomly select a candidate, service, vulnerability,
  attack-path edge, or score.
- A row reference into `pentest_design/CANDIDATES.md` must pin the full
  40-character source commit in `source_ref`; mutable row numbers are not
  reproducible provenance and are rejected by the validator.
- `candidate_paths` are composition hypotheses, not a claim that an agent
  must follow that path.
- A candidate is not deployable until its provenance, public-reproducer
  screen, vulnerable/fixed evidence, service compatibility, and resource
  effect have been reviewed.
- An approved path must satisfy the validator's explicit node-count,
  capability-continuity, knowledge-cost, and goal-reachability gates.

## Candidate-pool handoff for East Quay

Please continue adding candidates to the existing `pentest_design/CANDIDATES.md`;
MHBench+ will consume reviewed candidate IDs rather than mine or randomly pick
from the pool. For the East Quay shortlist, include the source/product/version
and fix or deployment-control evidence, PoC-screen status, attacker
precondition and capability gained, K1/K2/K3 and enumeration/protocol cost,
deployment feasibility, and the concrete East Quay workflow/resource each
candidate can affect. The useful handoff is a small, plausibly connected set
(3–5 nodes plus a few alternatives), not a dump of unrelated rows.

Prefer candidates that apply to real services or realistic deployed
weaknesses. If these cannot yield a coherent chain, allow a **minimal number**
of CVE-inspired behavioral analogs; an approved path is limited to one.
Record the originating CVE and the exact behavior being adapted, implement
and test both vulnerable and corrected controls, and describe it as an
analog—not as a CVE affecting the target product. An analog uses the distinct
`cve_inspired_analog` source track and
`public_poc_screen: inspiration_disclosed`; it is not a
`cve_no_public_poc` candidate and cannot be used to claim an unpublished/no-PoC
vulnerability or to supply a supposedly undisclosed K2 discovery gate. This
is a fallback, not the default source of the chain. If the source is classified
as having a public reproducer, include a direct reference to it.

## Current outputs and command path

The Compose renderer resolves service catalog references and produces:

- `docker-compose.yaml`;
- copied, relative build contexts and their Dockerfiles for customized
  services;
- network definitions, service attachments, health/dependency rules, and
  declared Compose-managed named volumes;
- optional reviewed weakness deployment overlays or digest-pinned images.

The Harbor task compiler wraps those outputs in the standard task layout and
generates an entry-only `instruction.md`. It refuses benchmark-ready packaging
without an approved weakness path; `--draft-preview` is limited to integration
smoke and must remain labeled **NOT benchmark-ready**.

The current commands are:

```bash
uv run python -m src.scenario.validate \
  examples/scenarios/east-quay-terminal/scenario.yaml \
  examples/scenarios/east-quay-terminal/range-plan.yaml

uv run python -m src.scenario.render_compose \
  --scenario examples/scenarios/east-quay-terminal/scenario.yaml \
  --range-plan examples/scenarios/east-quay-terminal/range-plan.yaml \
  --catalog examples/scenarios/east-quay-terminal/service-catalog.yaml \
  --catalog-root examples/scenarios/east-quay-terminal \
  --output /tmp/east-quay-range

./examples/scenarios/east-quay-terminal/smoke.sh
```

## Relationship to upstream MHBench

The original `src/models/network.py` / `NetworkTopology` / OpenStack path and
the new scenario-to-Compose path are currently separate. The Compose compiler
consumes the reviewed YAML inputs above; it does not yet convert an original
VM-oriented `NetworkTopology JSON` into a semantically reviewed
`scenario.yaml`/`range-plan.yaml`.

That separation is intentional for the first Harbor backend. Do not replace
or regress the VM backend to add Compose support. A later adapter may map
shared topology concepts, but it must not infer business purpose, weakness
applicability, or approved attack paths merely from host/subnet connectivity.

## East Quay service-coherence audit

The current East Quay business model ties services together in two distinct
ways:

1. **Port-to-yard workflow:** port operations records feed the dispatch
   integration; the integration publishes through NanoMQ; the yard-control
   process applies a bounded command and records a completion event. The
   passive observer records the broker-delivered command as independent
   verifier evidence. These services share a real runtime data/control flow.
2. **Warehouse workflow:** Open WES provides a real warehouse operator
   frontend, gateway, execution/station APIs, and its MySQL/Redis/Nacos
   dependencies. The scenario currently links it to port operations through a
   human handoff of the same shipment reference. It is **not** currently
   integrated into the dispatch worker or the yard-load authorization check.

The warehouse subsystem is therefore a plausible business department/system,
not yet a technical prerequisite or a vulnerability-chain hop. Keep it in the
demo only while the explicit product goal requires a recognizable warehouse
subsystem and its human shipment-reference handoff remains part of the normal
workflow. Before using it in a benchmark-ready chain, either establish and
test a justified connection to the target resource or defer it from the
playable range. Do not count its services as attack-chain nodes or add more
warehouse components simply to host vulnerabilities.

Each deployed weakness instance names the business `workflow_id` it affects.
Schema 1.1 verifies that the selected service participates in that workflow,
completing the vulnerability-to-service/system/workflow mapping rather than
relying only on free-form rationale.

`Workflow.system_interactions` distinguishes a software integration from a
human handoff. Cross-system `Flow` edges must be backed by a declared
`service_integration`, and every declared `service_integration` must have a
concrete flow in the range plan. Co-membership in a broad workflow or a
`human_handoff` does not authorize an invented technical edge, and every
interaction may reference only records declared by that workflow.

## Readiness snapshot

At the time this contract was written, East Quay is a runnable business-range
demo, not a playable pentest benchmark:

- the scenario has 3 normal workflows, 5 business systems, and 13 services;
- the range has 8 sourced candidate records, but 0 selected/deployed
  weaknesses and 0 approved candidate paths;
- Compose smoke checks the baseline workflow and network boundaries;
- a Harbor `nop` run scores 0.0 and confirms the negative verifier path;
- no positive exploit trial, approved 3+ node path, or benchmark-ready Harbor
  task has been demonstrated.

These counts are not inferred by this document; verify them from the current
YAML and rerun the validator before making a release claim.
