"""Validated input contract for semantically grounded cyber-range scenarios.

This is intentionally separate from ``src.models.network.NetworkTopology``:
the latter describes MHBench's existing VM-oriented range model, while these
models capture business semantics and portable service-level deployment intent.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


class SpecModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Department(SpecModel):
    id: str
    name: str
    purpose: str


class Actor(SpecModel):
    id: str
    name: str
    department_id: str | None = None
    description: str


class BusinessSystem(SpecModel):
    id: str
    name: str
    purpose: str
    department_ids: list[str] = Field(min_length=1)


class SystemInteraction(SpecModel):
    """A business-level link; distinguishes software calls from human handoffs."""

    id: str
    from_system_id: str
    to_system_id: str
    kind: Literal["service_integration", "human_handoff"]
    records: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def interaction_is_not_self_referential(self) -> "SystemInteraction":
        if self.from_system_id == self.to_system_id:
            raise ValueError(
                f"system interaction {self.id} must connect distinct systems"
            )
        return self


class Workflow(SpecModel):
    id: str
    name: str
    purpose: str
    actor_ids: list[str] = Field(min_length=1)
    system_ids: list[str] = Field(min_length=1)
    system_interactions: list[SystemInteraction] = Field(default_factory=list)
    records: list[str] = Field(default_factory=list)
    outcome: str


class NamedVolume(SpecModel):
    """A Compose-managed volume; host bind mounts are intentionally excluded."""

    id: str
    purpose: str

    @field_validator("id")
    @classmethod
    def validate_volume_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
            raise ValueError(
                "named volume id must be a Compose name, not a host path"
            )
        return value


class VolumeMount(SpecModel):
    """Mount a declared Compose volume at one container path."""

    volume_id: str
    target: str
    read_only: bool = False

    @field_validator("target")
    @classmethod
    def validate_mount_target(cls, value: str) -> str:
        target = PurePosixPath(value)
        if (
            not target.is_absolute()
            or ".." in target.parts
            or target == PurePosixPath("/")
        ):
            raise ValueError(
                "named-volume mount target must be an absolute container path "
                "other than '/' and cannot contain '..'"
            )
        return value


class ServiceInstance(SpecModel):
    id: str
    system_ids: list[str] = Field(min_length=1)
    catalog_ref: str
    role: str
    image: str | None = None
    dockerfile: str | None = None
    ports: list[int] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)
    entrypoint: str | list[str] | None = None
    command: str | list[str] | None = None
    volume_mounts: list[VolumeMount] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_runtime_overrides(self) -> "ServiceInstance":
        for label, value in (
            ("entrypoint", self.entrypoint),
            ("command", self.command),
        ):
            if value is not None and (
                not value
                or isinstance(value, list)
                and any(not item for item in value)
            ):
                raise ValueError(
                    f"service {self.id} {label} cannot be empty"
                )
        targets = [mount.target for mount in self.volume_mounts]
        if len(targets) != len(set(targets)):
            raise ValueError(
                f"service {self.id} has duplicate named-volume mount targets"
            )
        return self


class WeaknessInstance(SpecModel):
    """An explicitly selected/deployable weakness, linked to its candidate."""

    id: str
    candidate_id: str
    service_id: str
    workflow_id: str | None = None
    catalog_ref: str
    rationale: str


class PocSearchRecord(SpecModel):
    """Auditable per-source record for a public-reproducer screen."""

    source_family: Literal[
        "cve_org_record",
        "nvd_record",
        "vendor_advisory",
        "github",
        "gitlab",
        "exploit_db",
        "packet_storm",
        "metasploit",
        "nuclei",
        "web_search",
    ]
    fallback_for: list[
        Literal[
            "cve_org_record",
            "nvd_record",
            "vendor_advisory",
            "github",
            "gitlab",
            "exploit_db",
            "packet_storm",
            "metasploit",
            "nuclei",
        ]
    ] = Field(default_factory=list)
    query_scope: Literal[
        "identifier", "product_version", "sink", "root_cause", "references"
    ]
    checked_on: date
    query: str = Field(min_length=1)
    url: AnyHttpUrl
    classification: Literal["exact", "related", "not_found", "unavailable"]
    evidence_kind: Literal[
        "standalone_exploit",
        "reproduction_steps",
        "maintainer_regression_test",
        "public_advisory",
        "search_result",
    ] = "search_result"
    notes: str = Field(min_length=1)

    @field_validator("checked_on")
    @classmethod
    def reject_future_search_date(cls, value: date) -> date:
        if value > date.today():
            raise ValueError("PoC search checked_on date cannot be in the future")
        return value

    @model_validator(mode="after")
    def source_url_matches_family(self) -> "PocSearchRecord":
        expected_domains = {
            "cve_org_record": "cve.org",
            "nvd_record": "nvd.nist.gov",
            "github": "github.com",
            "gitlab": "gitlab.com",
            "exploit_db": "exploit-db.com",
            "packet_storm": "packetstormsecurity.com",
            "metasploit": "github.com",
            "nuclei": "github.com",
        }
        expected = expected_domains.get(self.source_family)
        hostname = (urlsplit(str(self.url)).hostname or "").lower()
        if expected and not (
            hostname == expected or hostname.endswith(f".{expected}")
        ):
            raise ValueError(
                f"{self.source_family} search URL must be hosted on "
                f"{expected}, got {hostname or '<missing host>'}"
            )
        if self.classification == "exact" and self.evidence_kind == "search_result":
            raise ValueError(
                "an exact reproducer search result must identify its evidence_kind"
            )
        return self


class KnowledgeThreshold(SpecModel):
    """Evidence-backed assessment of one pre-build difficulty threshold."""

    result: Literal["pending", "crossed", "not_crossed"] = "pending"
    evidence: str | None = None

    @model_validator(mode="after")
    def require_basis_for_verdict(self) -> "KnowledgeThreshold":
        if self.result != "pending" and not (self.evidence or "").strip():
            raise ValueError(
                "a non-pending knowledge-threshold verdict needs evidence"
            )
        return self


class KnowledgeThresholds(SpecModel):
    """K1: identify stack, K2: identify defect, K3: construct wire request."""

    k1: KnowledgeThreshold = Field(default_factory=KnowledgeThreshold)
    k2: KnowledgeThreshold = Field(default_factory=KnowledgeThreshold)
    k3: KnowledgeThreshold = Field(default_factory=KnowledgeThreshold)

    def crossed_count(self) -> int:
        return sum(
            threshold.result == "crossed"
            for threshold in (self.k1, self.k2, self.k3)
        )


class EnumerationAssessment(SpecModel):
    """Static estimate of the smallest search an attacker must perform."""

    status: Literal["pending", "acceptable", "too_small"] = "pending"
    surface: str | None = None
    authentication_state: str | None = None
    input_fields: list[str] = Field(default_factory=list)
    minimum_search_space: int | None = Field(default=None, ge=1)
    interaction_rounds: int | None = Field(default=None, ge=1)
    protocol_construction_required: bool | None = None
    rationale: str | None = None

    @model_validator(mode="after")
    def completed_assessment_has_dimensions(self) -> "EnumerationAssessment":
        if self.status != "pending" and (
            not self.surface
            or not self.authentication_state
            or not self.input_fields
            or self.minimum_search_space is None
            or self.interaction_rounds is None
            or self.protocol_construction_required is None
            or not (self.rationale or "").strip()
        ):
            raise ValueError(
                "a completed enumeration assessment must document surface, "
                "authentication, inputs, minimum search space, interaction "
                "rounds, protocol construction, and rationale"
            )
        return self


class CveInspiration(SpecModel):
    """Provenance for a CVE-inspired behavior adapted to a different target."""

    cve_id: str
    source_product: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    source_refs: list[AnyHttpUrl] = Field(min_length=1)
    public_reproducer_refs: list[AnyHttpUrl] = Field(default_factory=list)
    source_mechanism: str = Field(min_length=1)
    adaptation: str = Field(min_length=1)
    disclosure: Literal["public_advisory", "public_reproducer"]

    @field_validator("cve_id")
    @classmethod
    def validate_cve_identifier(cls, value: str) -> str:
        if not CVE_ID_PATTERN.fullmatch(value):
            raise ValueError("CVE inspiration must identify its source CVE")
        return value

    @model_validator(mode="after")
    def public_reproducer_has_reference(self) -> "CveInspiration":
        if self.disclosure == "public_reproducer" and not self.public_reproducer_refs:
            raise ValueError(
                "public CVE reproducer disclosure must include a direct reference"
            )
        if (
            self.public_reproducer_refs
            and self.disclosure != "public_reproducer"
        ):
            raise ValueError(
                "public reproducer references require public_reproducer disclosure"
            )
        return self


class WeaknessCandidate(SpecModel):
    """A sourced vulnerability candidate, not yet selected/deployed."""

    id: str
    source_track: Literal[
        "cve_no_public_poc",
        "silent_upstream_fix",
        "deployed_weakness",
        "cve_inspired_analog",
    ]
    source_ref: str
    product: str
    vulnerable_baseline: str
    fix_commit: str | None = None
    corrected_control_ref: str | None = None
    cve_id: str | None = None
    cve_inspiration: CveInspiration | None = None
    mechanism: str
    precondition: str
    requires_capabilities: list[str] = Field(min_length=1)
    grants_capabilities: list[str] = Field(min_length=1)
    resource_effects: list[str] = Field(min_length=1)
    environment_preconditions: list[str] = Field(default_factory=list)
    business_fit: str
    selection_band: Literal["core", "adjacent", "alternate", "deferred"]
    selection_rationale: str
    triage_status: Literal["candidate", "selected", "rejected"] = "candidate"
    artifact_pair_status: Literal[
        "unchecked",
        "registry-pair",
        "source-build-required",
        "deployment-control-pair",
        "unavailable",
    ] = "unchecked"
    public_poc_screen: Literal[
        "pending", "pass", "fail", "not_applicable", "inspiration_disclosed"
    ] = "pending"
    poc_searches: list["PocSearchRecord"] = Field(default_factory=list)
    case_role: Literal["primary", "chain_tissue", "excluded"] = "primary"
    knowledge_thresholds: KnowledgeThresholds = Field(
        default_factory=KnowledgeThresholds
    )
    enumeration: EnumerationAssessment = Field(
        default_factory=EnumerationAssessment
    )
    live_reproduction: Literal["pending", "pass", "fail"] = "pending"
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_provenance_and_poc_screen(self) -> "WeaknessCandidate":
        pool_mentions = re.findall(
            r"pentest_design/CANDIDATES\.md(?:@([0-9a-fA-F]{40}))?",
            self.source_ref,
        )
        if any(not snapshot for snapshot in pool_mentions):
            raise ValueError(
                f"candidate {self.id} must pin pentest_design/CANDIDATES.md "
                "row references to a full 40-character commit"
            )

        required_cve_sources = {
            "cve_org_record",
            "nvd_record",
            "vendor_advisory",
            "github",
            "gitlab",
            "exploit_db",
            "packet_storm",
            "metasploit",
            "nuclei",
            "web_search",
        }
        if self.source_track == "cve_no_public_poc":
            if self.cve_inspiration:
                raise ValueError(
                    f"CVE candidate {self.id} cannot also be labeled as a "
                    "CVE-inspired analog"
                )
            if not self.fix_commit:
                raise ValueError(
                    f"CVE candidate {self.id} must identify its fixed control"
                )
            if not self.cve_id or not CVE_ID_PATTERN.fullmatch(self.cve_id):
                raise ValueError(
                    f"CVE candidate {self.id} must declare its CVE identifier"
                )
            if self.public_poc_screen == "not_applicable":
                raise ValueError(
                    f"CVE candidate {self.id} cannot mark PoC screening "
                    "not applicable"
                )
            if self.public_poc_screen == "pass":
                searched = {record.source_family for record in self.poc_searches}
                missing = sorted(required_cve_sources - searched)
                if missing:
                    raise ValueError(
                        f"CVE candidate {self.id} cannot pass PoC screening; "
                        f"missing source families: {missing}"
                    )
                if any(
                    record.classification == "exact"
                    for record in self.poc_searches
                ):
                    raise ValueError(
                        f"CVE candidate {self.id} has an exact public PoC and "
                        "cannot pass screening"
                    )
                query_scopes = {record.query_scope for record in self.poc_searches}
                required_scopes = {
                    "identifier",
                    "product_version",
                    "sink",
                    "root_cause",
                }
                missing_scopes = sorted(required_scopes - query_scopes)
                if missing_scopes:
                    raise ValueError(
                        f"CVE candidate {self.id} cannot pass PoC screening; "
                        f"missing query scopes: {missing_scopes}"
                    )
                unavailable = {
                    record.source_family
                    for record in self.poc_searches
                    if record.classification == "unavailable"
                }
                fallbacks = {
                    source
                    for record in self.poc_searches
                    if record.source_family == "web_search"
                    for source in record.fallback_for
                }
                if not unavailable <= fallbacks:
                    raise ValueError(
                        f"CVE candidate {self.id} marks sources unavailable "
                        "without a corresponding domain-restricted web-search "
                        f"fallback: {sorted(unavailable - fallbacks)}"
                    )
                for record in self.poc_searches:
                    if record.fallback_for and (
                        record.source_family != "web_search"
                        or "site:" not in record.query.lower()
                    ):
                        raise ValueError(
                            f"CVE candidate {self.id} fallback searches must "
                            "be domain-restricted web_search queries"
                        )
        elif self.source_track == "cve_inspired_analog":
            if self.cve_id:
                raise ValueError(
                    f"CVE-inspired analog {self.id} must not claim the target "
                    "product is affected by the source CVE; use cve_inspiration"
                )
            if not self.cve_inspiration:
                raise ValueError(
                    f"CVE-inspired analog {self.id} must record source CVE "
                    "and adaptation provenance"
                )
            if self.fix_commit:
                raise ValueError(
                    f"CVE-inspired analog {self.id} must not present the "
                    "source product's fix as a target-product fix"
                )
            if not self.corrected_control_ref:
                raise ValueError(
                    f"CVE-inspired analog {self.id} must identify its own "
                    "corrected deployment control"
                )
            if self.public_poc_screen != "inspiration_disclosed":
                raise ValueError(
                    f"CVE-inspired analog {self.id} must mark its CVE source "
                    "as inspiration_disclosed and document the disclosure in "
                    "cve_inspiration"
                )
        elif self.cve_id or self.cve_inspiration:
            raise ValueError(
                f"non-CVE candidate {self.id} must not declare CVE provenance"
            )

        if self.source_track == "deployed_weakness":
            if self.public_poc_screen != "not_applicable":
                raise ValueError(
                    f"deployed weakness {self.id} must mark public PoC screen "
                    "not_applicable"
                )
            if not self.corrected_control_ref:
                raise ValueError(
                    f"deployed weakness {self.id} must identify its corrected "
                    "deployment control"
                )
            if self.fix_commit:
                raise ValueError(
                    f"deployed weakness {self.id} must not use fix_commit as a "
                    "substitute for its corrected deployment control"
                )
            if self.cve_inspiration:
                raise ValueError(
                    f"deployed weakness {self.id} cannot declare CVE inspiration"
                )
        elif (
            self.source_track != "cve_inspired_analog"
            and self.public_poc_screen
            in ("not_applicable", "inspiration_disclosed")
        ):
            raise ValueError(
                f"{self.source_track} candidate {self.id} requires a public "
                "PoC screening state"
            )
        elif (
            self.source_track != "cve_inspired_analog"
            and not self.fix_commit
        ):
            raise ValueError(
                f"{self.source_track} candidate {self.id} must identify its "
                "fixed upstream commit"
            )
        elif (
            self.source_track == "silent_upstream_fix"
            and self.public_poc_screen == "pass"
            and not self.poc_searches
        ):
            raise ValueError(
                f"silent-fix candidate {self.id} cannot pass the public "
                "reproducer screen without per-source search records"
            )
        if (
            self.source_track in ("cve_no_public_poc", "silent_upstream_fix")
            and self.public_poc_screen == "pass"
            and any(
                record.classification == "exact"
                and not (
                    self.source_track == "silent_upstream_fix"
                    and record.evidence_kind == "maintainer_regression_test"
                )
                for record in self.poc_searches
            )
        ):
            raise ValueError(
                f"candidate {self.id} has an exact disqualifying public reproducer and "
                "cannot pass screening"
            )
        return self


class ArtifactObservation(SpecModel):
    """Point-in-time evidence about buildable vulnerable/fixed artifacts."""

    checked_on: str
    candidate_ids: list[str] = Field(min_length=1)
    observation: str
    consequence: str


class EntryState(SpecModel):
    """Explicit initial access and capabilities supplied to the agent."""

    actor_id: str
    service_id: str
    authentication: Literal[
        "anonymous", "seeded-low-privilege", "provided-credentials"
    ]
    capabilities: list[str] = Field(min_length=1)
    description: str
    endpoint: str | None = None
    credentials: dict[str, str] = Field(default_factory=dict)


class AgentEnvironment(SpecModel):
    """Harbor's isolated attacker container and its explicitly reachable nets."""

    catalog_ref: str
    network_ids: list[str] = Field(min_length=1)
    tools: list[str] = Field(default_factory=list)


class Network(SpecModel):
    id: str
    purpose: str
    exposure: Literal["agent", "internal", "egress", "management"]


class NetworkAttachment(SpecModel):
    service_id: str
    network_id: str


class Flow(SpecModel):
    id: str
    from_service: str
    to_service: str
    protocol: str
    port: int
    purpose: str


class AttackTransition(SpecModel):
    id: str
    from_capability: str
    to_capability: str
    weakness_id: str


class CandidatePathHypothesis(SpecModel):
    """Explicit composition hypothesis over sourced candidate IDs."""

    id: str
    candidate_ids: list[str] = Field(min_length=2)
    target_goal_id: str
    target_capability: str | None = None
    primary_candidate_id: str | None = None
    rationale: str
    unresolved_gates: list[str] = Field(default_factory=list)
    status: Literal["hypothesis", "rejected", "approved"] = "hypothesis"

    @model_validator(mode="after")
    def approved_path_has_target(self) -> "CandidatePathHypothesis":
        if self.status == "approved" and not self.target_capability:
            raise ValueError(
                f"approved candidate path {self.id} must declare target_capability"
            )
        if self.status == "approved":
            if len(self.candidate_ids) < 3:
                raise ValueError(
                    f"approved candidate path {self.id} needs at least three "
                    "vulnerability nodes"
                )
            if self.primary_candidate_id not in self.candidate_ids:
                raise ValueError(
                    f"approved candidate path {self.id} must identify its "
                    "primary candidate within candidate_ids"
                )
        return self


class ResourceGoal(SpecModel):
    id: str
    description: str
    evidence_source: str
    target_capabilities: list[str] = Field(default_factory=list)
    weight: float = Field(gt=0)


class ScenarioPlan(SpecModel):
    """Level 1: business scenario, independent of concrete vulnerabilities."""

    schema_version: Literal["1.0", "1.1"]
    id: str
    title: str
    summary: str
    departments: list[Department] = Field(min_length=1)
    actors: list[Actor] = Field(min_length=1)
    systems: list[BusinessSystem] = Field(min_length=1)
    workflows: list[Workflow] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_business_model(self) -> "ScenarioPlan":
        collections = {
            "department": self.departments,
            "actor": self.actors,
            "system": self.systems,
            "workflow": self.workflows,
        }
        for label, items in collections.items():
            ids = [item.id for item in items]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {label} id in scenario plan")

        for system in self.systems:
            if len(system.department_ids) != len(set(system.department_ids)):
                raise ValueError(
                    f"system {system.id} repeats a department association"
                )
        for workflow in self.workflows:
            if len(workflow.actor_ids) != len(set(workflow.actor_ids)):
                raise ValueError(f"workflow {workflow.id} repeats an actor")
            if len(workflow.system_ids) != len(set(workflow.system_ids)):
                raise ValueError(f"workflow {workflow.id} repeats a system")
            if len(workflow.records) != len(set(workflow.records)):
                raise ValueError(f"workflow {workflow.id} repeats a record")
            interaction_ids = [
                interaction.id for interaction in workflow.system_interactions
            ]
            if len(interaction_ids) != len(set(interaction_ids)):
                raise ValueError(
                    f"workflow {workflow.id} repeats a system interaction id"
                )
            if self.schema_version == "1.0" and workflow.system_interactions:
                raise ValueError(
                    f"workflow {workflow.id} uses system_interactions, which "
                    "requires scenario schema 1.1"
                )
            for interaction in workflow.system_interactions:
                if (
                    interaction.from_system_id not in workflow.system_ids
                    or interaction.to_system_id not in workflow.system_ids
                ):
                    raise ValueError(
                        f"system interaction {interaction.id} references a "
                        f"system outside workflow {workflow.id}"
                    )
                undocumented_records = (
                    set(interaction.records) - set(workflow.records)
                )
                if undocumented_records:
                    raise ValueError(
                        f"system interaction {interaction.id} in workflow "
                        f"{workflow.id} references records not declared by that "
                        f"workflow: {sorted(undocumented_records)}"
                    )
        return self


class RangePlan(SpecModel):
    """Level 2: realize a ScenarioPlan as catalog-backed cyber-range assets."""

    schema_version: Literal["1.0", "1.1"]
    scenario_id: str
    entry_state: EntryState
    agent: AgentEnvironment | None = None
    candidate_selection_policy: Literal["deterministic-business-evidence-first"] = (
        "deterministic-business-evidence-first"
    )
    services: list[ServiceInstance] = Field(min_length=1)
    volumes: list[NamedVolume] = Field(default_factory=list)
    weakness_candidates: list[WeaknessCandidate] = Field(default_factory=list)
    artifact_observations: list[ArtifactObservation] = Field(default_factory=list)
    weaknesses: list[WeaknessInstance] = Field(default_factory=list)
    networks: list[Network] = Field(min_length=1)
    attachments: list[NetworkAttachment] = Field(min_length=1)
    flows: list[Flow] = Field(default_factory=list)
    attack_transitions: list[AttackTransition] = Field(default_factory=list)
    candidate_paths: list[CandidatePathHypothesis] = Field(default_factory=list)
    goals: list[ResourceGoal] = Field(min_length=1)

    def candidates_directly_reachable_from_entry(self) -> list[WeaknessCandidate]:
        """Return candidates whose declared requirements are met at entry."""
        entry_capabilities = set(self.entry_state.capabilities)
        return [
            candidate
            for candidate in self.weakness_candidates
            if set(candidate.requires_capabilities) <= entry_capabilities
        ]

    @model_validator(mode="after")
    def validate_internal_references(self) -> "RangePlan":
        if self.schema_version == "1.0" and any(
            candidate.source_track == "cve_inspired_analog"
            for candidate in self.weakness_candidates
        ):
            raise ValueError(
                "cve_inspired_analog requires range-plan schema 1.1"
            )

        def unique(items: list[object], label: str) -> dict[str, object]:
            indexed: dict[str, object] = {}
            for item in items:
                key = getattr(item, "id")
                if key in indexed:
                    raise ValueError(f"duplicate {label} id: {key}")
                indexed[key] = item
            return indexed

        services = unique(self.services, "service")
        weaknesses = unique(self.weaknesses, "weakness")
        candidates = unique(self.weakness_candidates, "weakness candidate")
        networks = unique(self.networks, "network")
        volumes = unique(self.volumes, "volume")
        unique(self.flows, "flow")
        unique(self.attack_transitions, "attack transition")
        unique(self.candidate_paths, "candidate path")
        unique(self.goals, "goal")

        def require(ref: str, index: dict[str, object], kind: str) -> None:
            if ref not in index:
                raise ValueError(f"unknown {kind} reference: {ref}")

        for service in self.services:
            for dependency in service.depends_on:
                require(dependency, services, "service")
            for mount in service.volume_mounts:
                require(mount.volume_id, volumes, "volume")

        for weakness in self.weaknesses:
            require(weakness.candidate_id, candidates, "weakness candidate")
            require(weakness.service_id, services, "service")
            candidate = candidates[weakness.candidate_id]
            assert isinstance(candidate, WeaknessCandidate)
            if candidate.triage_status != "selected":
                raise ValueError(
                    f"weakness {weakness.id} selects candidate "
                    f"{candidate.id} whose triage_status is "
                    f"{candidate.triage_status!r}, not 'selected'"
                )
            if self.schema_version == "1.1" and not weakness.workflow_id:
                raise ValueError(
                    f"weakness {weakness.id} must name its business workflow "
                    "in range schema 1.1"
                )
            if (
                candidate.source_track
                not in ("deployed_weakness", "cve_inspired_analog")
                and candidate.public_poc_screen != "pass"
            ):
                raise ValueError(
                    f"selected candidate {candidate.id} has not passed "
                    "the public PoC screen"
                )
            if candidate.live_reproduction != "pass":
                raise ValueError(
                    f"selected candidate {candidate.id} has not passed "
                    "live vulnerable/fixed reproduction"
                )
            valid_artifact_pairs = (
                {"deployment-control-pair"}
                if candidate.source_track
                in ("deployed_weakness", "cve_inspired_analog")
                else {"registry-pair", "source-build-required"}
            )
            if candidate.artifact_pair_status not in valid_artifact_pairs:
                raise ValueError(
                    f"selected candidate {candidate.id} has no verified "
                    "vulnerable/fixed or deployment-control artifact pair"
                )
            if candidate.case_role == "excluded":
                raise ValueError(
                    f"selected weakness {weakness.id} references candidate "
                    f"{candidate.id} marked excluded"
                )
            if candidate.enumeration.status == "pending":
                raise ValueError(
                    f"selected candidate {candidate.id} has no completed "
                    "enumeration assessment"
                )
            if candidate.case_role == "primary" and (
                candidate.enumeration.status != "acceptable"
                or candidate.knowledge_thresholds.crossed_count() == 0
            ):
                raise ValueError(
                    f"primary candidate {candidate.id} must pass the "
                    "enumeration screen and cross at least one K1/K2/K3 "
                    "knowledge threshold"
                )
            if (
                candidate.source_track == "cve_inspired_analog"
                and candidate.case_role == "primary"
                and candidate.knowledge_thresholds.k3.result != "crossed"
            ):
                raise ValueError(
                    f"primary CVE-inspired analog {candidate.id} must cross "
                    "K3 using the adapted protocol, not rely on source-CVE "
                    "mechanism discovery"
                )
        for network in self.networks:
            if not network.purpose.strip():
                raise ValueError(f"network {network.id} needs a purpose")
        for attachment in self.attachments:
            require(attachment.service_id, services, "service")
            require(attachment.network_id, networks, "network")
        if self.agent:
            for network_id in self.agent.network_ids:
                require(network_id, networks, "network")
                network = networks[network_id]
                assert isinstance(network, Network)
                if network.exposure != "agent":
                    raise ValueError(
                        f"agent may attach only to agent-exposure networks; "
                        f"{network_id} is {network.exposure!r}"
                    )
                if not any(
                    attachment.network_id == network_id
                    for attachment in self.attachments
                ):
                    raise ValueError(
                        f"agent-exposure network {network_id} has no "
                        "attached target service"
                    )
        for flow in self.flows:
            require(flow.from_service, services, "service")
            require(flow.to_service, services, "service")
        for transition in self.attack_transitions:
            require(transition.weakness_id, weaknesses, "weakness")
            weakness = weaknesses[transition.weakness_id]
            assert isinstance(weakness, WeaknessInstance)
            candidate = candidates[weakness.candidate_id]
            assert isinstance(candidate, WeaknessCandidate)
            if transition.from_capability not in candidate.requires_capabilities:
                raise ValueError(
                    f"transition {transition.id} starts from a capability "
                    f"not declared by candidate {candidate.id}"
                )
            if transition.to_capability not in candidate.grants_capabilities:
                raise ValueError(
                    f"transition {transition.id} grants a capability not "
                    f"declared by candidate {candidate.id}"
                )
        for observation in self.artifact_observations:
            for candidate_id in observation.candidate_ids:
                require(candidate_id, candidates, "weakness candidate")
        for path in self.candidate_paths:
            require(path.target_goal_id, {goal.id: goal for goal in self.goals}, "goal")
            if len(path.candidate_ids) != len(set(path.candidate_ids)):
                raise ValueError(f"candidate path {path.id} repeats a candidate")
            for candidate_id in path.candidate_ids:
                require(candidate_id, candidates, "weakness candidate")
            if path.status == "approved":
                if path.unresolved_gates:
                    raise ValueError(
                        f"approved candidate path {path.id} still has unresolved gates"
                    )
                cve_analog_count = 0
                for candidate_id in path.candidate_ids:
                    path_candidate = candidates[candidate_id]
                    assert isinstance(path_candidate, WeaknessCandidate)
                    cve_analog_count += (
                        path_candidate.source_track == "cve_inspired_analog"
                    )
                if cve_analog_count > 1:
                    raise ValueError(
                        f"approved candidate path {path.id} may contain at most "
                        "one CVE-inspired analog; prefer upstream or deployed "
                        "weaknesses for the remaining nodes"
                    )
                target_goal = next(
                    goal for goal in self.goals if goal.id == path.target_goal_id
                )
                if path.target_capability not in target_goal.target_capabilities:
                    raise ValueError(
                        f"approved candidate path {path.id} target_capability "
                        f"{path.target_capability!r} is not declared by resource "
                        f"goal {target_goal.id}"
                    )
                path_candidates = set(path.candidate_ids)
                deployed_candidates = {
                    weakness.candidate_id for weakness in self.weaknesses
                }
                if not path_candidates <= deployed_candidates:
                    missing = sorted(path_candidates - deployed_candidates)
                    raise ValueError(
                        f"approved candidate path {path.id} contains candidates "
                        f"not explicitly deployed as weaknesses: {missing}"
                    )
                primary = candidates[path.primary_candidate_id]
                assert isinstance(primary, WeaknessCandidate)
                if (
                    primary.case_role != "primary"
                    or primary.enumeration.status != "acceptable"
                    or primary.knowledge_thresholds.crossed_count() == 0
                ):
                    raise ValueError(
                        f"approved candidate path {path.id} primary candidate "
                        f"{primary.id} has not passed the K1/K2/K3 and "
                        "enumeration screens"
                    )
                if not any(
                    candidates[candidate_id].knowledge_thresholds.k3.result
                    == "crossed"
                    for candidate_id in path.candidate_ids
                ):
                    raise ValueError(
                        f"approved candidate path {path.id} has no candidate "
                        "with a demonstrated K3 protocol-construction cost"
                    )
                reachable = set(self.entry_state.capabilities)
                for candidate_id in path.candidate_ids:
                    candidate_grants: set[str] = set()
                    for transition in self.attack_transitions:
                        weakness = weaknesses[transition.weakness_id]
                        assert isinstance(weakness, WeaknessInstance)
                        if (
                            weakness.candidate_id == candidate_id
                            and transition.from_capability in reachable
                        ):
                            candidate_grants.add(transition.to_capability)
                    if not candidate_grants:
                        raise ValueError(
                            f"approved candidate path {path.id} is not a "
                            f"continuous chain at candidate {candidate_id}"
                        )
                    reachable.update(candidate_grants)
                if path.target_capability not in reachable:
                    raise ValueError(
                        f"approved candidate path {path.id} does not reach "
                        "target_capability after applying its ordered weakness "
                        "transitions"
                    )

        attached = {attachment.service_id for attachment in self.attachments}
        for service in self.services:
            if service.id not in attached:
                raise ValueError(f"service {service.id} is not attached to a network")
        return self


class ScenarioBundle(SpecModel):
    """Two-stage authoring input with cross-validation between its plans."""

    scenario: ScenarioPlan
    range: RangePlan

    @model_validator(mode="after")
    def validate_cross_references(self) -> "ScenarioBundle":
        if self.range.scenario_id != self.scenario.id:
            raise ValueError(
                f"range.scenario_id {self.range.scenario_id!r} does not match "
                f"scenario.id {self.scenario.id!r}"
            )
        if self.range.schema_version != self.scenario.schema_version:
            raise ValueError(
                "scenario and range-plan schema versions must match"
            )
        departments = {item.id for item in self.scenario.departments}
        actors = {item.id for item in self.scenario.actors}
        systems = {item.id for item in self.scenario.systems}
        system_services: dict[str, set[str]] = {}
        service_by_id = {item.id: item for item in self.range.services}

        for actor in self.scenario.actors:
            if actor.department_id and actor.department_id not in departments:
                raise ValueError(
                    f"actor {actor.id} references unknown department "
                    f"{actor.department_id}"
                )
        if self.range.entry_state.actor_id not in actors:
            raise ValueError(
                f"entry state references unknown actor "
                f"{self.range.entry_state.actor_id}"
            )
        if self.range.entry_state.service_id not in service_by_id:
            raise ValueError(
                f"entry state references unknown service "
                f"{self.range.entry_state.service_id}"
            )
        for system in self.scenario.systems:
            for department_id in system.department_ids:
                if department_id not in departments:
                    raise ValueError(
                        f"system {system.id} references unknown department "
                        f"{department_id}"
                    )
        for workflow in self.scenario.workflows:
            for actor_id in workflow.actor_ids:
                if actor_id not in actors:
                    raise ValueError(
                        f"workflow {workflow.id} references unknown actor {actor_id}"
                    )
            for system_id in workflow.system_ids:
                if system_id not in systems:
                    raise ValueError(
                        f"workflow {workflow.id} references unknown system {system_id}"
                    )
            for interaction in workflow.system_interactions:
                for system_id in (
                    interaction.from_system_id,
                    interaction.to_system_id,
                ):
                    if system_id not in systems:
                        raise ValueError(
                            f"system interaction {interaction.id} references "
                            f"unknown system {system_id}"
                        )
        for service in self.range.services:
            for system_id in service.system_ids:
                if system_id not in systems:
                    raise ValueError(
                        f"service {service.id} references unknown business system "
                        f"{system_id}"
                    )
                system_services.setdefault(system_id, set()).add(service.id)

        for workflow in self.scenario.workflows:
            for system_id in workflow.system_ids:
                if system_id not in system_services:
                    raise ValueError(
                        f"workflow {workflow.id} references system {system_id} "
                        "with no concrete service in the range plan"
                    )
            workflow_departments = {
                department_id
                for system_id in workflow.system_ids
                for system in self.scenario.systems
                if system.id == system_id
                for department_id in system.department_ids
            }
            for actor_id in workflow.actor_ids:
                actor = next(
                    actor for actor in self.scenario.actors if actor.id == actor_id
                )
                if (
                    actor.department_id is not None
                    and actor.department_id not in workflow_departments
                ):
                    raise ValueError(
                        f"workflow {workflow.id} includes actor {actor.id} from "
                        f"department {actor.department_id}, but none of its "
                        "business systems involve that department"
                    )

        workflow_systems = {
            system_id
            for workflow in self.scenario.workflows
            for system_id in workflow.system_ids
        }
        unused_systems = systems - workflow_systems
        if unused_systems:
            raise ValueError(
                "business systems must participate in at least one workflow: "
                f"{sorted(unused_systems)}"
            )

        workflows_by_id = {
            workflow.id: workflow for workflow in self.scenario.workflows
        }
        for weakness in self.range.weaknesses:
            if weakness.workflow_id is None:
                continue
            workflow = workflows_by_id.get(weakness.workflow_id)
            if workflow is None:
                raise ValueError(
                    f"weakness {weakness.id} references unknown workflow "
                    f"{weakness.workflow_id}"
                )
            service = service_by_id[weakness.service_id]
            if not set(service.system_ids) & set(workflow.system_ids):
                raise ValueError(
                    f"weakness {weakness.id} service {service.id} is not part "
                    f"of workflow {workflow.id}"
                )

        for flow in self.range.flows:
            source = service_by_id[flow.from_service]
            target = service_by_id[flow.to_service]
            if set(source.system_ids) & set(target.system_ids):
                continue
            # Co-membership in a broad workflow is not enough to justify an
            # invented service edge: require an explicit software integration
            # distinct from a human handoff.
            related = any(
                interaction.kind == "service_integration"
                and interaction.from_system_id in source.system_ids
                and interaction.to_system_id in target.system_ids
                for workflow in self.scenario.workflows
                for interaction in workflow.system_interactions
            )
            if not related:
                raise ValueError(
                    f"flow {flow.id} crosses business systems without an "
                    "explicit service_integration; a human_handoff does not "
                    "authorize a technical service edge"
                )
        for workflow in self.scenario.workflows:
            for interaction in workflow.system_interactions:
                if interaction.kind != "service_integration":
                    continue
                realized = any(
                    interaction.from_system_id
                    in service_by_id[flow.from_service].system_ids
                    and interaction.to_system_id
                    in service_by_id[flow.to_service].system_ids
                    for flow in self.range.flows
                )
                if not realized:
                    raise ValueError(
                        f"service integration {interaction.id} in workflow "
                        f"{workflow.id} has no corresponding concrete service flow"
                    )

        attached_networks: dict[str, set[str]] = {
            service_id: set() for service_id in service_by_id
        }
        for attachment in self.range.attachments:
            attached_networks[attachment.service_id].add(attachment.network_id)
        for flow in self.range.flows:
            if not (
                attached_networks[flow.from_service]
                & attached_networks[flow.to_service]
            ):
                raise ValueError(
                    f"flow {flow.id} connects services without a shared "
                    "network attachment"
                )
        return self
