# Optional LLM refinement of a range skeleton

MHBench+ should produce a deterministic, runnable **range skeleton**: a
candidate service topology, network boundaries, business-system relationships,
sourced weakness leads, resource goals, and deployment artifacts. It is not
expected to autonomously invent a complete industry scenario or discover a
valid exploit chain.

An LLM may refine that skeleton into a more coherent Harbor case. This is an
offline authoring step, not a dependency of the MHBench generator, Compose
renderer, Harbor task compiler, or task runtime:

```text
Human scenario brief + MHBench range skeleton
                     |
                     v
        Optional LLM-assisted refinement
        (proposed edits + explicit gaps)
                     |
          human review / approval
                     |
                     v
 deterministic schema, evidence and deployment validation
                     |
                     v
       Compose environment + Harbor task
```

The LLM's job is to improve the **case**, not make unverified security claims.
It can improve the scenario narrative, align department and workflow
descriptions with the services that actually exist, identify missing business
relationships, draft player-facing entry instructions, and propose a small
amount of justified integration glue. It must preserve concrete service and
network constraints unless it explicitly proposes a change for human review.

## Required behavior

When given a scenario brief, `scenario.yaml`, `range-plan.yaml`,
`service-catalog.yaml`, and available Harbor assets, the LLM should:

1. Return proposed file-level edits, not claim it changed or deployed anything.
2. Keep departments, systems, workflows, services, and resource goals
   causally connected. Do not add a service just to increase host or
   vulnerability count.
3. Prefer existing catalogued services. Surface unsupported product needs as
   gaps; do not invent plausible-sounding products or create a large bespoke
   subsystem silently.
4. Preserve attacker/target/verifier separation. Never add
   `network_mode: public`, host networking, host mounts, Docker sockets, or
   shared host PID/IPC namespaces.
5. Treat vulnerability candidates as untrusted research leads. Do not invent
   CVEs, fixes, public-PoC search results, exploitability, or evidence.
   Candidate selection and deployment remain explicit and must satisfy the
   repository's evidence gates.
6. Treat an attack path as a reviewed composition hypothesis, not a required
   sequence for the tested agent. Do not turn the proposed path into
   player-facing instructions.
7. Keep `instruction.md` limited to the entry point, available tools, and
   environment. Do not expose hidden resources, attack paths, verifier
   implementation, or scoring weights.
8. Ground verifier decisions in independently collected resource state,
   protected artifacts, or observed service/proxy evidence. Never award
   progress from agent narration or self-reported flags.
9. Distinguish verified facts from proposals and list unresolved evidence or
   implementation gaps.

## Expected response

The authoring response should contain:

- **Coherence review:** supported business workflow/service relationships and
  any unnatural or disconnected links.
- **Proposed edits:** unified diffs or complete replacement contents for only
  the files that need changes (normally scenario/range YAML and authored
  README/task assets).
- **Unresolved gaps:** unsupported services, missing normal workflow behavior,
  missing vulnerability evidence, and unverified verifier assumptions.
- **Validation plan:** exact deterministic commands and runtime checks to run
  after human approval.

The LLM must not label a case benchmark-ready. Only deterministic validators,
deployment smoke tests, evidence review, and an approved candidate path can
establish readiness.

## Human approval and deterministic gate

Review all proposed changes before applying them. Then run the scenario
validator and Compose smoke test. Run the Harbor task compiler, Harbor lint,
and Harbor runtime checks only when appropriate for the current readiness
stage; an explicit draft preview is for environment/compiler integration only,
not a benchmark-ready task.

Final artifacts remain ordinary checked-in YAML, Docker build contexts, Harbor
assets, and Compose output. No LLM API key or provider-specific feature is
required to build, deploy, reset, or score the task.
