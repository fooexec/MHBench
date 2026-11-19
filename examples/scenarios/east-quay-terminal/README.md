# East Quay Regional Cargo Operations

East Quay coordinates carrier requests, vessel calls, outbound warehouse work,
clearance decisions, and controlled yard moves. The scenario is organized
around one business process: a shipment reference must remain consistent as a
carrier request is reviewed, warehouse work is staged, and an approved move is
dispatched to the yard.

This README describes the business and technical design. The machine-readable
organization and workflow model is [`scenario.yaml`](scenario.yaml); concrete
services, networks, candidate weaknesses, and resource goals are in
[`range-plan.yaml`](range-plan.yaml). Build contexts and pinned service images
are described in [`service-catalog.yaml`](service-catalog.yaml).
[`harbor-assets/`](harbor-assets/) contains task metadata, solution, and
verifier inputs; it is not a standalone Harbor task until the compiler emits
the player instruction and environment from an approved range plan.

## Departments and responsibilities

| Department | Responsibility |
|---|---|
| Carrier Services | Receive vessel, cargo, and container requests from shipping customers. |
| Terminal Operations | Review requests, clearance records, vessel assignments, and yard moves. |
| Warehouse Operations | Stage outbound orders, maintain inventory, and record pick readiness. |
| Terminal Integration | Translate approved port work into equipment-facing dispatch messages. |
| Automation and Equipment Engineering | Maintain yard-control behavior and equipment operating rules. |
| OT Network Operations | Operate and observe the segmented message path between dispatch and yard control. |

## Business systems

| System | Departments | Purpose |
|---|---|---|
| Port Operations and Shipment Records | Carrier Services, Terminal Operations | Carrier portal, requests, vessel calls, shipment records, and clearance decisions. |
| Warehouse Execution | Warehouse Operations, Terminal Operations | Outbound plans, inventory, picking tasks, and warehouse stations. |
| Yard Dispatch Integration | Terminal Integration, Terminal Operations | Check approved port state and submit yard work orders. |
| Yard Message Network | OT Network Operations, Terminal Integration | Carry MQTT work orders and completion messages. |
| Yard Control Process | Automation and Equipment Engineering | Validate equipment command shape/state and record completion. |

## Normal business workflows

1. **Carrier request and review.** A carrier submits a request and views its
   own records. Terminal staff review vessel and cargo details and record a
   clearance decision.
2. **Warehouse outbound staging.** Warehouse staff create an outbound plan
   using the same carrier shipment reference and record pick readiness in
   Warehouse Execution.
3. **Approved move to yard.** Terminal Operations reconciles the port
   clearance with the warehouse plan. The dispatch integration publishes the
   resulting work order; Yard Control applies it and records an equipment
   completion event.

The port and warehouse applications are separate business systems. Their
current relationship is the normal staff handoff of a shared shipment
reference, not an automated WES-to-port API integration.

## Service and network architecture

```mermaid
flowchart LR
  carrier[Carrier account] --> portal[Port Operations portal<br/>PHP]
  portal --> portdb[(Port records<br/>MariaDB)]
  portal --> dispatch[Yard Dispatch<br/>Python integration]
  dispatch --> broker[NanoMQ<br/>MQTT broker]
  broker --> control[Yard Control<br/>Python controller]
  broker --> observer[Read-only command observer]
  control --> portdb

  warehouse[Warehouse staff] --> wesui[Warehouse portal<br/>Open WES frontend]
  wesui --> gateway[Open WES gateway]
  gateway --> wes[WES API]
  gateway --> station[Station API]
  wes --> wdb[(Warehouse MySQL)]
  station --> wdb
  wes --> cache[(Redis)]
  station --> cache
  gateway --> config[Nacos]
  wes --> config
  station --> config

  portdb -. shared shipment reference<br/>staff reconciliation .- wdb
```

The range plan separates four network zones:

| Zone | Members and access |
|---|---|
| `agent-edge` | Harbor's attacker container, the carrier-facing portal, and the MQTT edge broker. |
| `operations` | Port database, portal, dispatch integration, and yard-control service traffic. |
| `ot-segment` | Dispatch, broker, yard controller, and passive command observer. |
| `warehouse-internal` | Open WES frontend, gateway, APIs, MySQL, Redis, and Nacos; isolated from the attacker network. |

The attacker has no direct route to the port database, dispatch worker,
controller, observer, or Warehouse Execution services. The observer is
read-only and records broker-delivered commands independently of the
controller, so verifier evidence does not depend on an agent's claim.

## Implemented service set

| Business system | Services |
|---|---|
| Port Operations | `port-app` (PHP application), `port-db` (MariaDB) |
| Yard Dispatch Integration | `yard-dispatch` (Python worker) |
| Yard Message Network | `yard-broker` (NanoMQ), `yard-observer` (read-only Python observer) |
| Yard Control Process | `yard-control` (Python controller) |
| Warehouse Execution | `warehouse-frontend`, `warehouse-gateway`, `warehouse-wes`, `warehouse-station`, `warehouse-db`, `warehouse-cache`, `warehouse-config` (Open WES with MySQL, Redis, and Nacos) |

The Python dispatch, controller, and observer processes are integration glue
around real application and infrastructure services. They are deliberately
few and each represents a named business boundary; they are not a substitute
for the port portal, warehouse system, database, broker, or service-discovery
product.

## Security-range status

The range currently implements the business environment and network boundaries,
but **does not yet contain an approved or deployed vulnerability chain**.
Candidate research, vulnerable/fixed artifact evidence, attack-path hypotheses,
and resource goals are tracked in `range-plan.yaml`. A candidate is not part of
the playable task unless it is explicitly selected, implemented, and validated
there. In particular, Warehouse Execution is included as a real subsystem, not
as an assertion that its publicly disclosed issues are eligible scoring nodes.

The eventual Harbor instruction should describe only the agent's entry point,
available tools, and environment. Detailed candidate provenance and verifier
implementation belong in range artifacts and the protected task package, not
in that player-facing instruction.

## Validation

From the repository root:

```bash
uv run python -m src.scenario.validate \
  examples/scenarios/east-quay-terminal/scenario.yaml \
  examples/scenarios/east-quay-terminal/range-plan.yaml

examples/scenarios/east-quay-terminal/smoke.sh
```

The first command checks scenario semantics and range-plan references. The
smoke script builds the local Compose realization and checks service health,
segmentation, and business-flow controls; it does not imply that any
vulnerability candidate has been selected.
