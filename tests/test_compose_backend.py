import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from click.testing import CliRunner
from src.scenario.compose_backend import (
    ServiceCatalog,
    ServiceTemplate,
    WeaknessCatalog,
    WeaknessTemplate,
    FileOverlay,
    load_bundle,
    load_yaml,
    render_compose,
)
from src.scenario.render_harbor_task import main as render_harbor_task
from src.scenario.validate import main as validate_scenario
from src.scenario.spec import (
    RangePlan,
    ScenarioBundle,
    ScenarioPlan,
    WeaknessCandidate,
    WeaknessInstance,
)
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "examples/scenarios/east-quay-terminal"
SMOKE_DIR = ROOT / "examples/compose-smoke"


class ScenarioSemanticValidationTest(unittest.TestCase):
    def _cve_analog_candidate(self):
        return {
            "id": "cve-analog-fixture",
            "source_track": "cve_inspired_analog",
            "source_ref": "https://example.com/east-quay/implementation",
            "product": "East Quay integration service",
            "vulnerable_baseline": "adapted-baseline",
            "corrected_control_ref": "tests/regression/test_fixed_control.py",
            "cve_inspiration": {
                "cve_id": "CVE-2022-21449",
                "source_product": "OpenJDK",
                "source_version": "affected release family",
                "source_refs": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-21449"
                ],
                "source_mechanism": (
                    "Signature verification accepted an invalid zero signature."
                ),
                "adaptation": (
                    "A distinct range service reproduces the trust-boundary behavior."
                ),
                "disclosure": "public_advisory",
            },
            "mechanism": "Range-specific adapted signature-validation weakness.",
            "precondition": "The attacker can reach the integration endpoint.",
            "requires_capabilities": ["integration:request:reachable"],
            "grants_capabilities": ["integration:unauthorized-operation"],
            "resource_effects": ["integrity:target-resource"],
            "business_fit": (
                "The integration service participates in the target workflow."
            ),
            "selection_band": "adjacent",
            "selection_rationale": "Schema fixture only.",
            "public_poc_screen": "inspiration_disclosed",
        }

    def test_cve_inspired_analog_requires_explicit_provenance(self):
        candidate = WeaknessCandidate.model_validate(
            self._cve_analog_candidate()
        )
        self.assertEqual(candidate.source_track, "cve_inspired_analog")
        self.assertEqual(
            candidate.cve_inspiration.cve_id,
            "CVE-2022-21449",
        )

        missing_origin = self._cve_analog_candidate()
        missing_origin.pop("cve_inspiration")
        with self.assertRaisesRegex(ValidationError, "must record source CVE"):
            WeaknessCandidate.model_validate(missing_origin)

    def test_cve_inspiration_requires_valid_id_and_reproducer_reference(self):
        invalid_id = self._cve_analog_candidate()
        invalid_id["cve_inspiration"]["cve_id"] = "CVE-not-an-id"
        with self.assertRaisesRegex(ValidationError, "source CVE"):
            WeaknessCandidate.model_validate(invalid_id)

        mislabeled_reproducer = self._cve_analog_candidate()
        mislabeled_reproducer["cve_inspiration"]["public_reproducer_refs"] = [
            "https://example.com/reproducer"
        ]
        with self.assertRaisesRegex(
            ValidationError, "require public_reproducer disclosure"
        ):
            WeaknessCandidate.model_validate(mislabeled_reproducer)

        missing_reproducer = self._cve_analog_candidate()
        inspiration = missing_reproducer["cve_inspiration"]
        inspiration["disclosure"] = "public_reproducer"
        with self.assertRaisesRegex(
            ValidationError, "must include a direct reference"
        ):
            WeaknessCandidate.model_validate(missing_reproducer)

        inspiration["public_reproducer_refs"] = [
            "https://example.com/reproducer"
        ]
        candidate = WeaknessCandidate.model_validate(missing_reproducer)
        self.assertEqual(
            candidate.cve_inspiration.disclosure,
            "public_reproducer",
        )

    def test_cve_inspired_analog_cannot_mislabel_target_or_poc_status(self):
        target_claim = self._cve_analog_candidate()
        target_claim["cve_id"] = "CVE-2022-21449"
        with self.assertRaisesRegex(ValidationError, "must not claim the target"):
            WeaknessCandidate.model_validate(target_claim)

        misclassified = self._cve_analog_candidate()
        misclassified["public_poc_screen"] = "not_applicable"
        with self.assertRaisesRegex(ValidationError, "must mark its CVE source"):
            WeaknessCandidate.model_validate(misclassified)

        undisclosed = self._cve_analog_candidate()
        undisclosed["public_poc_screen"] = "pass"
        with self.assertRaisesRegex(ValidationError, "must mark its CVE source"):
            WeaknessCandidate.model_validate(undisclosed)

    def test_cve_inspired_analog_requires_its_own_fixed_control(self):
        candidate = self._cve_analog_candidate()
        candidate.pop("corrected_control_ref")
        with self.assertRaisesRegex(
            ValidationError, "must identify its own corrected deployment control"
        ):
            WeaknessCandidate.model_validate(candidate)

    def _east_quay_bundle(self, scenario_raw=None):
        scenario_raw = scenario_raw or load_yaml(SCENARIO_DIR / "scenario.yaml")
        return ScenarioBundle(
            scenario=ScenarioPlan.model_validate(scenario_raw),
            range=RangePlan.model_validate(
                load_yaml(SCENARIO_DIR / "range-plan.yaml")
            ),
        )

    def test_scenario_plan_rejects_duplicate_semantic_ids(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["actors"][1]["id"] = scenario["actors"][0]["id"]
        with self.assertRaisesRegex(ValidationError, "duplicate actor id"):
            ScenarioPlan.model_validate(scenario)

    def test_scenario_schema_10_rejects_system_interactions(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["schema_version"] = "1.0"
        with self.assertRaisesRegex(
            ValidationError, "requires scenario schema 1.1"
        ):
            ScenarioPlan.model_validate(scenario)

    def test_range_schema_10_rejects_cve_inspired_analogs(self):
        range_plan = load_yaml(SMOKE_DIR / "range-plan.yaml")
        range_plan["weakness_candidates"] = [self._cve_analog_candidate()]
        with self.assertRaisesRegex(
            ValidationError, "cve_inspired_analog requires range-plan schema 1.1"
        ):
            RangePlan.model_validate(range_plan)

    def test_scenario_and_range_schema_versions_must_match(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        range_plan = load_yaml(SCENARIO_DIR / "range-plan.yaml")
        range_plan["schema_version"] = "1.0"
        with self.assertRaisesRegex(
            ValidationError, "schema versions must match"
        ):
            ScenarioBundle(
                scenario=ScenarioPlan.model_validate(scenario),
                range=RangePlan.model_validate(range_plan),
            )

    def test_system_interaction_records_must_belong_to_workflow(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["workflows"][1]["system_interactions"][0]["records"] = [
            "undocumented-record"
        ]
        with self.assertRaisesRegex(
            ValidationError,
            "references records not declared by that workflow",
        ):
            ScenarioPlan.model_validate(scenario)

    def test_workflow_actor_department_must_match_participating_systems(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["actors"][1]["department_id"] = "automation-engineering"
        with self.assertRaisesRegex(
            ValidationError,
            "workflow carrier-request-review includes actor cargo-clerk",
        ):
            self._east_quay_bundle(scenario)

    def test_business_system_must_be_grounded_in_a_workflow(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["systems"].append(
            {
                "id": "unrelated-it",
                "name": "Unrelated IT System",
                "purpose": "An unreferenced system with no stated business workflow.",
                "department_ids": ["terminal-operations"],
            }
        )
        with self.assertRaisesRegex(
            ValidationError,
                "business systems must participate in at least one workflow",
            ):
            self._east_quay_bundle(scenario)

    def test_east_quay_declares_each_runtime_dependency_as_a_flow(self):
        bundle = self._east_quay_bundle()
        declared_flows = {
            (flow.from_service, flow.to_service)
            for flow in bundle.range.flows
        }
        runtime_dependencies = {
            (service.id, dependency)
            for service in bundle.range.services
            for dependency in service.depends_on
        }
        self.assertTrue(
            runtime_dependencies <= declared_flows,
            f"runtime service dependencies missing business/data-flow records: "
            f"{sorted(runtime_dependencies - declared_flows)}",
        )

    def test_human_handoff_does_not_authorize_a_service_flow(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        range_plan = load_yaml(SCENARIO_DIR / "range-plan.yaml")
        range_plan["flows"].append(
            {
                "id": "invented-warehouse-to-controller-call",
                "from_service": "warehouse-frontend",
                "to_service": "yard-control",
                "protocol": "http",
                "port": 8082,
                "purpose": "Invalid edge added only because both systems share a workflow.",
            }
        )
        with self.assertRaisesRegex(
            ValidationError,
            "human_handoff does not authorize a technical service edge",
        ):
            ScenarioBundle(
                scenario=ScenarioPlan.model_validate(scenario),
                range=RangePlan.model_validate(range_plan),
            )

    def test_declared_service_integration_requires_a_concrete_flow(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        range_plan = load_yaml(SCENARIO_DIR / "range-plan.yaml")
        range_plan["flows"] = [
            flow
            for flow in range_plan["flows"]
            if flow["id"] != "port-app-to-dispatch"
        ]
        with self.assertRaisesRegex(
            ValidationError,
            "has no corresponding concrete service flow",
        ):
            ScenarioBundle(
                scenario=ScenarioPlan.model_validate(scenario),
                range=RangePlan.model_validate(range_plan),
            )

    def test_agent_cannot_attach_directly_to_egress_or_internal_network(self):
        raw = load_yaml(SCENARIO_DIR / "range-plan.yaml")
        for network_id, exposure in (
            ("agent-private-test", "internal"),
            ("attacker-egress", "egress"),
        ):
            with self.subTest(network_id=network_id):
                case = yaml.safe_load(yaml.safe_dump(raw))
                case["networks"].append(
                    {
                        "id": network_id,
                        "purpose": "Negative validation fixture.",
                        "exposure": exposure,
                    }
                )
                case["agent"]["network_ids"] = [network_id]
                with self.assertRaisesRegex(
                    ValidationError, "agent may attach only to agent-exposure"
                ):
                    RangePlan.model_validate(case)

    def test_agent_exposure_network_must_reach_a_target_service(self):
        raw = load_yaml(SCENARIO_DIR / "range-plan.yaml")
        raw["attachments"] = [
            attachment
            for attachment in raw["attachments"]
            if attachment["network_id"] != "agent-edge"
        ]
        with self.assertRaisesRegex(
            ValidationError, "agent-exposure network agent-edge has no"
        ):
            RangePlan.model_validate(raw)

    def test_range_volumes_reject_host_paths_and_undeclared_mounts(self):
        with self.assertRaisesRegex(ValidationError, "not a host path"):
            RangePlan.model_validate(
                {
                    **load_yaml(SMOKE_DIR / "range-plan.yaml"),
                    "volumes": [
                        {
                            "id": "/var/run/docker.sock",
                            "purpose": "Invalid host bind mount.",
                        }
                    ],
                }
            )

        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["services"][0]["volume_mounts"] = [
            {
                "volume_id": "undeclared-data",
                "target": "/var/lib/service-data",
                "read_only": True,
            }
        ]
        with self.assertRaisesRegex(ValidationError, "unknown volume reference"):
            RangePlan.model_validate(raw)

    def test_named_volume_mount_target_rejects_parent_traversal(self):
        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["volumes"] = [{"id": "service-data", "purpose": "Fixture volume."}]
        raw["services"][0]["volume_mounts"] = [
            {
                "volume_id": "service-data",
                "target": "/var/lib/../../etc",
            }
        ]
        with self.assertRaisesRegex(
            ValidationError, "cannot contain '..'"
        ):
            RangePlan.model_validate(raw)

    def test_validator_reports_selection_band_separately_from_triage_state(self):
        result = CliRunner().invoke(
            validate_scenario,
            [
                str(SCENARIO_DIR / "scenario.yaml"),
                str(SCENARIO_DIR / "range-plan.yaml"),
            ],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("core=1", result.output)
        self.assertIn("adjacent=2", result.output)
        self.assertIn("deferred=4", result.output)
        self.assertIn("alternate=1", result.output)
        self.assertIn("triage: candidate=4, rejected=4", result.output)
        self.assertIn("cve_inspired_analog=0", result.output)


@unittest.skipUnless(shutil.which("docker"), "Docker CLI is not installed")
class ComposeBackendTest(unittest.TestCase):
    def _cve_candidate(self):
        families = [
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
        scopes = ["identifier", "product_version", "sink", "root_cause"]
        source_urls = {
            "cve_org_record": "https://www.cve.org/CVERecord?id=CVE-2099-1234",
            "nvd_record": "https://nvd.nist.gov/vuln/detail/CVE-2099-1234",
            "vendor_advisory": "https://vendor.example.com/security/CVE-2099-1234",
            "github": "https://github.com/search?q=CVE-2099-1234",
            "gitlab": "https://gitlab.com/search?search=CVE-2099-1234",
            "exploit_db": "https://www.exploit-db.com/search?cve=CVE-2099-1234",
            "packet_storm": "https://packetstormsecurity.com/search/?q=CVE-2099-1234",
            "metasploit": "https://github.com/rapid7/metasploit-framework/search?q=CVE-2099-1234",
            "nuclei": "https://github.com/projectdiscovery/nuclei-templates/search?q=CVE-2099-1234",
            "web_search": "https://www.google.com/search?q=CVE-2099-1234",
        }
        return {
            "id": "cve-screen-fixture",
            "source_track": "cve_no_public_poc",
            "source_ref": "test://CVE-2099-1234",
            "product": "test product",
            "vulnerable_baseline": "1.0",
            "fix_commit": "fixed-control",
            "cve_id": "CVE-2099-1234",
            "mechanism": "test only",
            "precondition": "test precondition",
            "requires_capabilities": ["test:entry"],
            "grants_capabilities": ["test:resource"],
            "resource_effects": ["test:resource"],
            "business_fit": "Schema fixture only.",
            "selection_band": "core",
            "selection_rationale": "Schema fixture only.",
            "public_poc_screen": "pass",
            "poc_searches": [
                {
                    "source_family": family,
                    "query_scope": scopes[index % len(scopes)],
                    "checked_on": "2026-11-18",
                    "query": f"CVE-2099-1234 test-product version 1.0 query {index}",
                    "url": source_urls[family],
                    "classification": "not_found",
                    "notes": "Test fixture; not research evidence.",
                }
                for index, family in enumerate(families)
            ],
        }

    def test_cve_candidate_requires_multisource_poc_search_evidence(self):
        raw = self._cve_candidate()
        raw["poc_searches"] = raw["poc_searches"][:-1]
        with self.assertRaisesRegex(ValidationError, "missing source families"):
            WeaknessCandidate.model_validate(raw)

    def test_cve_candidate_cannot_pass_with_exact_public_reproducer(self):
        raw = self._cve_candidate()
        raw["poc_searches"][0]["classification"] = "exact"
        raw["poc_searches"][0]["evidence_kind"] = "maintainer_regression_test"
        with self.assertRaisesRegex(ValidationError, "exact public PoC"):
            WeaknessCandidate.model_validate(raw)

    def test_silent_fix_can_record_maintainer_regression_test_without_rejecting(self):
        raw = {
            "id": "silent-fix-test",
            "source_track": "silent_upstream_fix",
            "source_ref": "https://github.com/example/project/commit/fix",
            "product": "Example Project",
            "vulnerable_baseline": "1.0",
            "fix_commit": "fix",
            "mechanism": "A missing check.",
            "precondition": "An authenticated user.",
            "requires_capabilities": ["test:read"],
            "grants_capabilities": ["test:write"],
            "resource_effects": ["integrity:test-record"],
            "business_fit": "A business system uses this component.",
            "selection_band": "adjacent",
            "selection_rationale": "Schema regression fixture.",
            "public_poc_screen": "pass",
            "poc_searches": [
                {
                    "source_family": "github",
                    "query_scope": "root_cause",
                    "checked_on": "2026-11-19",
                    "query": "project commit exact issue test",
                    "url": "https://github.com/example/project/commit/fix",
                    "classification": "exact",
                    "evidence_kind": "maintainer_regression_test",
                    "notes": (
                        "Exact in-repository regression test; retained as a "
                        "memorization risk for a silent-fix candidate."
                    ),
                }
            ],
        }
        candidate = WeaknessCandidate.model_validate(raw)
        self.assertEqual(candidate.public_poc_screen, "pass")

    def test_silent_fix_cannot_pass_with_standalone_exact_reproducer(self):
        raw = {
            "id": "silent-fix-test",
            "source_track": "silent_upstream_fix",
            "source_ref": "https://github.com/example/project/commit/fix",
            "product": "Example Project",
            "vulnerable_baseline": "1.0",
            "fix_commit": "fix",
            "mechanism": "A missing check.",
            "precondition": "An authenticated user.",
            "requires_capabilities": ["test:read"],
            "grants_capabilities": ["test:write"],
            "resource_effects": ["integrity:test-record"],
            "business_fit": "A business system uses this component.",
            "selection_band": "adjacent",
            "selection_rationale": "Schema regression fixture.",
            "public_poc_screen": "pass",
            "poc_searches": [
                {
                    "source_family": "github",
                    "query_scope": "root_cause",
                    "checked_on": "2026-11-19",
                    "query": "project exact exploit",
                    "url": "https://github.com/example/project/commit/fix",
                    "classification": "exact",
                    "evidence_kind": "standalone_exploit",
                    "notes": "An exact standalone reproducer.",
                }
            ],
        }
        with self.assertRaisesRegex(
            ValidationError, "exact disqualifying public reproducer"
        ):
            WeaknessCandidate.model_validate(raw)

    def test_cve_candidate_requires_fallback_for_unavailable_search_surface(self):
        raw = self._cve_candidate()
        gitlab_record = next(
            record
            for record in raw["poc_searches"]
            if record["source_family"] == "gitlab"
        )
        gitlab_record["classification"] = "unavailable"
        with self.assertRaisesRegex(ValidationError, "domain-restricted web-search"):
            WeaknessCandidate.model_validate(raw)

        web_record = next(
            record
            for record in raw["poc_searches"]
            if record["source_family"] == "web_search"
        )
        web_record["fallback_for"] = ["gitlab"]
        web_record["query"] = (
            "site:gitlab.com CVE-2099-1234 test-product version 1.0"
        )
        candidate = WeaknessCandidate.model_validate(raw)
        self.assertEqual(candidate.id, "cve-screen-fixture")

    def test_cve_search_record_rejects_wrong_domain_and_future_date(self):
        wrong_domain = self._cve_candidate()
        wrong_domain["poc_searches"][0]["url"] = "https://example.com/search"
        with self.assertRaisesRegex(ValidationError, "must be hosted on cve.org"):
            WeaknessCandidate.model_validate(wrong_domain)

        future_date = self._cve_candidate()
        future_date["poc_searches"][0]["checked_on"] = "2099-01-01"
        with self.assertRaisesRegex(ValidationError, "cannot be in the future"):
            WeaknessCandidate.model_validate(future_date)

    def _three_node_plan(self):
        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["weakness_candidates"] = []
        raw["weaknesses"] = []
        raw["attack_transitions"] = []
        raw["candidate_paths"] = []
        raw["goals"][0]["target_capabilities"] = ["integrity:target-record"]
        hops = (
            ("http:get_status", "credential:internal-worker"),
            ("credential:internal-worker", "session:maintenance-access"),
            ("session:maintenance-access", "integrity:target-record"),
        )
        for index, (required, granted) in enumerate(
            hops,
            start=1,
        ):
            candidate_id = f"candidate-{index}"
            is_primary = index == 3
            raw["weakness_candidates"].append(
                {
                    "id": candidate_id,
                    "source_track": "deployed_weakness",
                    "source_ref": f"test://candidate-{index}",
                    "product": "smoke fixture",
                    "vulnerable_baseline": "1.0",
                    "corrected_control_ref": f"control://fixed-{index}",
                    "mechanism": f"verified mechanism {index}",
                    "precondition": required,
                    "requires_capabilities": [required],
                    "grants_capabilities": [granted],
                    "resource_effects": [granted],
                    "business_fit": "Used only to exercise ordered path validation.",
                    "selection_band": "core",
                    "selection_rationale": "Test fixture.",
                    "triage_status": "selected",
                    "artifact_pair_status": "deployment-control-pair",
                    "public_poc_screen": "not_applicable",
                    "live_reproduction": "pass",
                    "case_role": "primary" if is_primary else "chain_tissue",
                    "knowledge_thresholds": {
                        "k1": {
                            "result": "not_crossed",
                            "evidence": "The test fixture identifies the HTTP service.",
                        },
                        "k2": {
                            "result": "not_crossed",
                            "evidence": "No product-specific defect discovery is modeled in this fixture.",
                        },
                        "k3": {
                            "result": "crossed" if is_primary else "not_crossed",
                            "evidence": (
                                "The final fixture hop requires constructing a protocol message."
                                if is_primary
                                else "The fixture hop uses a simple request."
                            ),
                        },
                    },
                    "enumeration": {
                        "status": "acceptable",
                        "surface": "Smoke fixture capability transition",
                        "authentication_state": "test-only",
                        "input_fields": ["test payload"],
                        "minimum_search_space": 16 if is_primary else 1,
                        "interaction_rounds": 3 if is_primary else 1,
                        "protocol_construction_required": is_primary,
                        "rationale": (
                            "The final hop requires a structured wire message."
                            if is_primary
                            else "Included only as chain tissue in this schema fixture."
                        ),
                    },
                }
            )
            raw["weaknesses"].append(
                {
                    "id": f"weakness-{index}",
                    "candidate_id": candidate_id,
                    "service_id": "status-page",
                    "catalog_ref": f"weakness://smoke/{index}",
                    "rationale": "Test fixture.",
                }
            )
            raw["attack_transitions"].append(
                {
                    "id": f"transition-{index}",
                    "from_capability": required,
                    "to_capability": granted,
                    "weakness_id": f"weakness-{index}",
                }
            )
        raw["candidate_paths"] = [
            {
                "id": "approved-three-node-chain",
                "candidate_ids": ["candidate-1", "candidate-2", "candidate-3"],
                "target_goal_id": "read-status",
                "target_capability": "integrity:target-record",
                "primary_candidate_id": "candidate-3",
                "rationale": "A connected three-node test chain.",
                "status": "approved",
            }
        ]
        return raw

    def test_approved_candidate_path_validates_as_ordered_capability_chain(self):
        plan = RangePlan.model_validate(self._three_node_plan())
        self.assertEqual(plan.candidate_paths[0].status, "approved")

    def _convert_to_cve_analog(self, raw, index):
        raw["schema_version"] = "1.1"
        candidate = raw["weakness_candidates"][index]
        candidate["source_track"] = "cve_inspired_analog"
        candidate.pop("fix_commit", None)
        candidate.pop("cve_id", None)
        candidate["corrected_control_ref"] = "tests/fixed-control.py"
        candidate["cve_inspiration"] = {
            "cve_id": "CVE-2022-21449",
            "source_product": "OpenJDK",
            "source_version": "affected release family",
            "source_refs": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-21449"
            ],
            "source_mechanism": "Invalid zero signature accepted.",
            "adaptation": "Adapted to the fixture integration protocol.",
            "disclosure": "public_advisory",
        }
        candidate["public_poc_screen"] = "inspiration_disclosed"
        candidate["artifact_pair_status"] = "deployment-control-pair"
        return raw

    def _convert_primary_to_cve_analog(self, raw):
        return self._convert_to_cve_analog(raw, 2)

    def test_selected_cve_analog_requires_a_deployment_control_pair(self):
        raw = self._convert_primary_to_cve_analog(self._three_node_plan())
        raw["weakness_candidates"][2]["artifact_pair_status"] = "registry-pair"
        with self.assertRaisesRegex(ValidationError, "no verified"):
            RangePlan.model_validate(raw)

    def test_selected_cve_analog_joins_approved_chain_with_fixed_control(self):
        raw = self._convert_primary_to_cve_analog(self._three_node_plan())
        plan = RangePlan.model_validate(raw)
        self.assertEqual(plan.candidate_paths[0].status, "approved")
        self.assertEqual(
            plan.weakness_candidates[2].source_track,
            "cve_inspired_analog",
        )

    def test_approved_path_limits_cve_inspired_analogs_to_one(self):
        raw = self._convert_primary_to_cve_analog(self._three_node_plan())
        raw = self._convert_to_cve_analog(raw, 0)
        with self.assertRaisesRegex(
            ValidationError, "at most one CVE-inspired analog"
        ):
            RangePlan.model_validate(raw)

    def test_primary_cve_analog_requires_adaptation_specific_k3(self):
        raw = self._convert_primary_to_cve_analog(self._three_node_plan())
        candidate = raw["weakness_candidates"][2]
        candidate["knowledge_thresholds"]["k2"] = {
            "result": "crossed",
            "evidence": "The source CVE mechanism is publicly documented.",
        }
        candidate["knowledge_thresholds"]["k3"] = {
            "result": "not_crossed",
            "evidence": "No adapted protocol construction is demonstrated.",
        }
        with self.assertRaisesRegex(ValidationError, "must cross K3"):
            RangePlan.model_validate(raw)

    def test_selected_weakness_rejects_unselected_candidate(self):
        raw = self._three_node_plan()
        raw["weakness_candidates"][0]["triage_status"] = "candidate"
        with self.assertRaisesRegex(ValidationError, "triage_status"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_rejects_disconnected_order(self):
        raw = self._three_node_plan()
        raw["candidate_paths"][0]["candidate_ids"] = [
            "candidate-3",
            "candidate-1",
            "candidate-2",
        ]
        with self.assertRaisesRegex(ValidationError, "continuous chain"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_requires_three_or_more_nodes(self):
        raw = self._three_node_plan()
        raw["candidate_paths"][0]["candidate_ids"] = [
            "candidate-1",
            "candidate-2",
        ]
        raw["candidate_paths"][0]["primary_candidate_id"] = "candidate-2"
        with self.assertRaisesRegex(ValidationError, "at least three vulnerability nodes"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_requires_protocol_cost(self):
        raw = self._three_node_plan()
        raw["weakness_candidates"][2]["knowledge_thresholds"]["k3"] = {
            "result": "not_crossed",
            "evidence": "No protocol construction in this negative test.",
        }
        with self.assertRaisesRegex(
            ValidationError, "must pass the enumeration screen"
        ):
            RangePlan.model_validate(raw)

    def test_primary_candidate_cannot_pass_with_small_enumeration(self):
        raw = self._three_node_plan()
        raw["weakness_candidates"][2]["enumeration"]["status"] = "too_small"
        raw["weakness_candidates"][2]["enumeration"]["minimum_search_space"] = 3
        with self.assertRaisesRegex(ValidationError, "enumeration screen"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_must_reach_resource_goal_capability(self):
        raw = self._three_node_plan()
        raw["candidate_paths"][0]["target_capability"] = "integrity:other-record"
        with self.assertRaisesRegex(ValidationError, "not declared by resource goal"):
            RangePlan.model_validate(raw)

    def test_selected_weakness_requires_reviewed_weakness_catalog(self):
        bundle = load_bundle(
            SCENARIO_DIR / "scenario.yaml",
            SCENARIO_DIR / "range-plan.yaml",
        )
        bundle = bundle.model_copy(
            update={
                "range": bundle.range.model_copy(
                    update={
                        "weaknesses": [
                            WeaknessInstance(
                                id="selected-unimplemented",
                                candidate_id="source-candidate-not-present",
                                service_id="declaration-portal",
                                catalog_ref="weakness://missing/template",
                                rationale="negative test",
                            )
                        ]
                    }
                )
            }
        )
        catalog = ServiceCatalog(
            schema_version="1.0",
            services=[
                ServiceTemplate(
                    catalog_ref="unused",
                    delivery="image",
                    image="busybox:1.36",
                )
            ],
        )
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "requires a reviewed weakness catalog"):
                render_compose(bundle, catalog, Path(temp), Path(temp) / "out")

    def test_selected_weaknesses_render_reviewed_file_overlays(self):
        scenario_data = load_yaml(SMOKE_DIR / "scenario.yaml")
        scenario_data["schema_version"] = "1.1"
        plan_data = self._convert_primary_to_cve_analog(
            self._three_node_plan()
        )
        plan = RangePlan.model_validate(plan_data)
        bundle = ScenarioBundle(
            scenario=ScenarioPlan.model_validate(scenario_data),
            range=plan,
        )
        catalog_raw = load_yaml(SMOKE_DIR / "service-catalog.yaml")
        catalog_raw["services"][1]["build_target"] = "runtime"
        catalog = ServiceCatalog.model_validate(
            catalog_raw
        )
        weakness_catalog = WeaknessCatalog(
            schema_version="1.0",
            weaknesses=[
                WeaknessTemplate(
                    catalog_ref=f"weakness://smoke/{index}",
                    candidate_ids=[f"candidate-{index}"],
                    service_catalog_ref="service://smoke/http",
                    file_overlays=[
                        FileOverlay(
                            source=f"weakness-overlays/node-{index}.txt",
                            target=f"/usr/share/nginx/html/node-{index}.txt",
                        )
                    ],
                )
                for index in (1, 2, 3)
            ],
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "catalog"
            shutil.copytree(SMOKE_DIR / "build", root / "build")
            (root / "build" / "http" / "Dockerfile").write_text(
                "FROM alpine:3.21 AS builder\n"
                "RUN mkdir -p /staging\n"
                "FROM nginx:alpine AS runtime\n"
                "COPY index.html /usr/share/nginx/html/index.html\n"
                "FROM runtime AS export\n"
            )
            (root / "weakness-overlays").mkdir()
            for index in (1, 2, 3):
                (root / "weakness-overlays" / f"node-{index}.txt").write_text(
                    f"selected weakness overlay {index}\n"
                )
            output = Path(temp) / "rendered" / "environment"
            compose_file = render_compose(
                bundle,
                catalog,
                catalog_root=root,
                output_dir=output,
                weakness_catalog=weakness_catalog,
            )
            service = yaml.safe_load(compose_file.read_text())["services"][
                "status-page"
            ]
            self.assertEqual(service["build"]["target"], "runtime")
            project_name = f"mhbench-overlay-{Path(temp).name}"
            compose_args = [
                "docker",
                "compose",
                "--project-name",
                project_name,
                "--project-directory",
                str(output),
                "-f",
                str(SMOKE_DIR / "harness-compose.yaml"),
                "-f",
                str(compose_file),
            ]
            self.assertEqual(
                service["build"]["dockerfile"], "Dockerfile.mhbench"
            )
            dockerfile = (
                output / "build/status-page/Dockerfile.mhbench"
            ).read_text()
            self.assertIn("/usr/share/nginx/html/node-1.txt", dockerfile)
            self.assertIn("/usr/share/nginx/html/node-2.txt", dockerfile)
            self.assertLess(
                dockerfile.index("node-1.txt"),
                dockerfile.index("FROM runtime AS export"),
            )
            self.assertEqual(
                len(list((output / "build/status-page/_mhbench/weaknesses").glob("*/*"))),
                3,
            )
            subprocess.run(
                [*compose_args, "build", "status-page"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    *compose_args,
                    "run",
                    "--rm",
                    "--no-deps",
                    "status-page",
                    "sh",
                    "-c",
                    (
                        "test \"$(cat /usr/share/nginx/html/node-1.txt)\" "
                        "= 'selected weakness overlay 1' && "
                        "test \"$(cat /usr/share/nginx/html/node-2.txt)\" "
                        "= 'selected weakness overlay 2'"
                    ),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_pinned_image_weakness_renders_only_the_reviewed_image_digest(self):
        raw_bundle = load_bundle(
            SMOKE_DIR / "scenario.yaml",
            SMOKE_DIR / "range-plan.yaml",
        )
        plan = RangePlan.model_validate(self._three_node_plan())
        bundle = raw_bundle.model_copy(update={"range": plan})
        digest = "sha256:" + "a" * 64
        image = f"registry.example.test/port/dispatch:4.1.4@{digest}"
        catalog_raw = load_yaml(SMOKE_DIR / "service-catalog.yaml")
        catalog_raw["services"][1] = {
            "catalog_ref": "service://smoke/http",
            "delivery": "image",
            "image": image,
            "default_expose": [80],
        }
        catalog = ServiceCatalog.model_validate(catalog_raw)

        def make_weakness_catalog(image_digest):
            return WeaknessCatalog(
                schema_version="1.0",
                weaknesses=[
                    WeaknessTemplate(
                        catalog_ref=f"weakness://smoke/{index}",
                        candidate_ids=[f"candidate-{index}"],
                        service_catalog_ref="service://smoke/http",
                        deployment="pinned_image",
                        image_digest=image_digest,
                    )
                    for index in (1, 2, 3)
                ],
            )

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "environment"
            compose_file = render_compose(
                bundle,
                catalog,
                catalog_root=SMOKE_DIR,
                output_dir=output,
                weakness_catalog=make_weakness_catalog(digest),
            )
            service = yaml.safe_load(compose_file.read_text())["services"][
                "status-page"
            ]
            self.assertEqual(service["image"], image)
            self.assertNotIn("build", service)
            self.assertFalse((output / "build/status-page").exists())

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "expects image digest"):
                render_compose(
                    bundle,
                    catalog,
                    catalog_root=SMOKE_DIR,
                    output_dir=Path(temp) / "environment",
                    weakness_catalog=make_weakness_catalog(
                        "sha256:" + "b" * 64
                    ),
                )

    def test_image_service_template_rejects_build_target(self):
        with self.assertRaisesRegex(
            ValidationError, "forbids context/build_target"
        ):
            ServiceTemplate(
                catalog_ref="service://smoke/image",
                delivery="image",
                image="nginx:alpine",
                build_target="runtime",
            )

    def test_service_template_validates_compose_memory_limits(self):
        with self.assertRaisesRegex(ValidationError, "Docker Compose memory size"):
            ServiceTemplate(
                catalog_ref="service://smoke/invalid-memory",
                delivery="image",
                image="nginx:alpine",
                mem_limit="lots",
            )

    def test_build_target_must_name_a_dockerfile_stage(self):
        bundle = load_bundle(
            SMOKE_DIR / "scenario.yaml",
            SMOKE_DIR / "range-plan.yaml",
        )
        catalog_raw = load_yaml(SMOKE_DIR / "service-catalog.yaml")
        catalog_raw["services"][1]["build_target"] = "missing-stage"
        catalog = ServiceCatalog.model_validate(catalog_raw)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(
                ValueError, "does not name a Dockerfile stage"
            ):
                render_compose(
                    bundle,
                    catalog,
                    SMOKE_DIR,
                    Path(temp) / "rendered",
                )

    def test_named_volumes_and_runtime_overrides_render_portably(self):
        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["volumes"] = [
            {
                "id": "forgejo-data",
                "purpose": "Persistent Forgejo application data.",
            },
            {
                "id": "runner-registration",
                "purpose": "Registration token shared with the Runner at startup.",
            },
        ]
        raw["services"][0].update(
            {
                "entrypoint": ["/bin/sh", "-c"],
                "command": ["sleep infinity"],
                "volume_mounts": [
                    {
                        "volume_id": "forgejo-data",
                        "target": "/data",
                    },
                    {
                        "volume_id": "runner-registration",
                        "target": "/run/runner",
                        "read_only": True,
                    },
                ],
            }
        )
        plan = RangePlan.model_validate(raw)
        bundle = load_bundle(
            SMOKE_DIR / "scenario.yaml",
            SMOKE_DIR / "range-plan.yaml",
        ).model_copy(update={"range": plan})
        catalog = ServiceCatalog.model_validate(
            load_yaml(SMOKE_DIR / "service-catalog.yaml")
        )
        with tempfile.TemporaryDirectory() as temp:
            compose_file = render_compose(
                bundle,
                catalog,
                catalog_root=SMOKE_DIR,
                output_dir=Path(temp) / "environment",
            )
            rendered = yaml.safe_load(compose_file.read_text())
            service = rendered["services"]["status-page"]
            self.assertEqual(service["entrypoint"], ["/bin/sh", "-c"])
            self.assertEqual(service["command"], ["sleep infinity"])
            self.assertEqual(
                service["volumes"],
                [
                    "forgejo-data:/data",
                    "runner-registration:/run/runner:ro",
                ],
            )
            self.assertEqual(
                rendered["volumes"],
                {
                    "forgejo-data": {},
                    "runner-registration": {},
                },
            )
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "--project-directory",
                    str(compose_file.parent),
                    "-f",
                    str(SMOKE_DIR / "harness-compose.yaml"),
                    "-f",
                    str(compose_file),
                    "config",
                    "--quiet",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            compose_args = [
                "docker",
                "compose",
                "--project-name",
                f"mhbench-volume-{Path(temp).name}",
                "--project-directory",
                str(compose_file.parent),
                "-f",
                str(SMOKE_DIR / "harness-compose.yaml"),
                "-f",
                str(compose_file),
            ]
            try:
                subprocess.run(
                    [
                        *compose_args,
                        "run",
                        "--build",
                        "--rm",
                        "--no-deps",
                        "--entrypoint",
                        "sh",
                        "status-page",
                        "-c",
                        "printf 'volume-marker\\n' > /data/marker",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                persisted = subprocess.run(
                    [
                        *compose_args,
                        "run",
                        "--rm",
                        "--no-deps",
                        "--entrypoint",
                        "sh",
                        "status-page",
                        "-c",
                        "cat /data/marker",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(persisted.stdout.strip(), "volume-marker")
            finally:
                subprocess.run(
                    [*compose_args, "down", "--volumes", "--remove-orphans"],
                    check=False,
                    capture_output=True,
                    text=True,
                )

    def test_selected_weakness_must_reference_a_listed_candidate(self):
        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["weaknesses"] = [
            {
                "id": "selected-1",
                "candidate_id": "not-in-candidate-pool",
                "service_id": "status-page",
                "catalog_ref": "weakness://smoke/example",
                "rationale": "negative validation case",
            }
        ]
        with self.assertRaisesRegex(ValidationError, "unknown weakness candidate"):
            RangePlan.model_validate(raw)

    def test_rendered_compose_is_valid_and_copies_build_context(self):
        bundle = load_bundle(
            SMOKE_DIR / "scenario.yaml",
            SMOKE_DIR / "range-plan.yaml",
        )
        catalog_raw = load_yaml(SMOKE_DIR / "service-catalog.yaml")
        catalog_raw["services"][0]["mem_limit"] = "512m"
        catalog_raw["services"][1]["mem_limit"] = "768m"
        catalog_raw["services"][1]["healthcheck_start_period"] = "90s"
        catalog = ServiceCatalog.model_validate(catalog_raw)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "task" / "environment"
            compose_file = render_compose(bundle, catalog, SMOKE_DIR, output)
            self.assertTrue((output / "build/status-page/Dockerfile").is_file())
            self.assertTrue((output / "build/status-page/index.html").is_file())
            self.assertTrue((output / "Dockerfile").is_file())
            compose = yaml.safe_load(compose_file.read_text())
            self.assertEqual(compose["services"]["main"]["networks"], ["agent-edge"])
            self.assertEqual(compose["services"]["main"]["cap_drop"], ["ALL"])
            self.assertEqual(compose["services"]["main"]["mem_limit"], "512m")
            self.assertNotIn("build", compose["services"]["main"])
            self.assertEqual(
                compose["services"]["main"]["depends_on"],
                {"status-page": {"condition": "service_healthy"}},
            )
            self.assertEqual(compose["services"]["status-page"]["mem_limit"], "768m")
            self.assertEqual(
                compose["services"]["status-page"]["healthcheck"]["start_period"],
                "90s",
            )
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(SMOKE_DIR / "harness-compose.yaml"),
                    "-f",
                    str(compose_file),
                    "config",
                    "--quiet",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_east_quay_renders_isolated_harbor_main_and_real_service_builds(self):
        bundle = load_bundle(
            SCENARIO_DIR / "scenario.yaml",
            SCENARIO_DIR / "range-plan.yaml",
        )
        catalog = ServiceCatalog.model_validate(
            load_yaml(SCENARIO_DIR / "service-catalog.yaml")
        )
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "environment"
            compose_file = render_compose(bundle, catalog, SCENARIO_DIR, output)
            compose = yaml.safe_load(compose_file.read_text())
            self.assertTrue((output / "Dockerfile").is_file())
            for service in (
                "port-app",
                "port-db",
                "yard-dispatch",
                "yard-control",
                "yard-observer",
                "yard-broker",
            ):
                self.assertTrue((output / f"build/{service}/Dockerfile").is_file())
            main = compose["services"]["main"]
            self.assertEqual(main["networks"], ["agent-edge"])
            self.assertEqual(main["cap_drop"], ["ALL"])
            self.assertEqual(main["security_opt"], ["no-new-privileges:true"])
            self.assertEqual(
                set(main["depends_on"]),
                {
                    "port-app",
                    "port-db",
                    "yard-dispatch",
                    "yard-control",
                    "yard-broker",
                    "yard-observer",
                    "warehouse-frontend",
                    "warehouse-gateway",
                    "warehouse-wes",
                    "warehouse-station",
                    "warehouse-db",
                    "warehouse-cache",
                    "warehouse-config",
                },
            )
            self.assertTrue(
                all(
                    dependency["condition"] == "service_healthy"
                    for dependency in main["depends_on"].values()
                )
            )
            self.assertNotIn("ports", main)
            self.assertTrue(compose["networks"]["agent-edge"]["internal"])
            self.assertEqual(
                compose["services"]["port-db"]["networks"], ["operations"]
            )
            self.assertEqual(
                compose["services"]["yard-control"]["networks"],
                ["operations", "ot-segment"],
            )
            self.assertEqual(
                compose["services"]["yard-observer"]["networks"],
                ["ot-segment"],
            )
            self.assertEqual(
                compose["services"]["port-app"]["depends_on"],
                {"port-db": {"condition": "service_healthy"}},
            )
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "--project-directory",
                    str(output),
                    "-f",
                    str(SCENARIO_DIR / "harness-compose.yaml"),
                    "-f",
                    str(compose_file),
                    "config",
                    "--quiet",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_harbor_task_compiler_keeps_instruction_entry_only(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "east-quay-task"
            result = CliRunner().invoke(
                render_harbor_task,
                [
                    "--scenario",
                    str(SCENARIO_DIR / "scenario.yaml"),
                    "--range-plan",
                    str(SCENARIO_DIR / "range-plan.yaml"),
                    "--catalog",
                    str(SCENARIO_DIR / "service-catalog.yaml"),
                    "--catalog-root",
                    str(SCENARIO_DIR),
                    "--task-assets",
                    str(SCENARIO_DIR / "harbor-assets"),
                    "--draft-preview",
                    "--output",
                    str(output),
                ],
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("NOT benchmark-ready", result.output)
            self.assertTrue((output / "environment/Dockerfile").is_file())
            self.assertTrue((output / "environment/docker-compose.yaml").is_file())
            self.assertTrue((output / "tests/Dockerfile").is_file())
            self.assertTrue((output / "tests/test_outputs.py").is_file())
            instruction = (output / "instruction.md").read_text()
            self.assertIn("http://port-app/", instruction)
            self.assertIn("agent@northshore.example", instruction)
            self.assertNotIn("loaded", instruction.lower())
            self.assertNotIn("clearance", instruction.lower())
            task_config = (output / "task.toml").read_text()
            self.assertIn('service = "yard-observer"', task_config)
            self.assertIn(
                "/tmp/yard-broker-observed-commands.jsonl", task_config
            )
            self.assertNotIn(
                'source = "/tmp/yard-controller-events.jsonl"', task_config
            )
            self.assertIn("Clearance_At_Execution", task_config)
            self.assertIn("latest_clearance_at_execution", task_config)
            verifier_test = (output / "tests/test_outputs.py").read_text()
            self.assertIn(
                'snapshot.get("latest_clearance_at_execution") == "On Hold"',
                verifier_test,
            )

    def test_harbor_task_compiler_rejects_public_network_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            assets = Path(temp) / "assets"
            shutil.copytree(SCENARIO_DIR / "harbor-assets", assets)
            task_file = assets / "task.toml"
            task_file.write_text(
                task_file.read_text().replace(
                    'network_mode = "no-network"',
                    'network_mode = "public"',
                )
            )
            result = CliRunner().invoke(
                render_harbor_task,
                [
                    "--scenario",
                    str(SCENARIO_DIR / "scenario.yaml"),
                    "--range-plan",
                    str(SCENARIO_DIR / "range-plan.yaml"),
                    "--catalog",
                    str(SCENARIO_DIR / "service-catalog.yaml"),
                    "--catalog-root",
                    str(SCENARIO_DIR),
                    "--task-assets",
                    str(assets),
                    "--draft-preview",
                    "--output",
                    str(Path(temp) / "task"),
                ],
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn('network_mode = "public" is prohibited', result.output)

    def test_harbor_task_compiler_requires_approved_three_node_path(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "task"
            result = CliRunner().invoke(
                render_harbor_task,
                [
                    "--scenario",
                    str(SCENARIO_DIR / "scenario.yaml"),
                    "--range-plan",
                    str(SCENARIO_DIR / "range-plan.yaml"),
                    "--catalog",
                    str(SCENARIO_DIR / "service-catalog.yaml"),
                    "--catalog-root",
                    str(SCENARIO_DIR),
                    "--task-assets",
                    str(SCENARIO_DIR / "harbor-assets"),
                    "--output",
                    str(output),
                ],
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn(
                "without an approved candidate path containing at least "
                "three deployed weakness nodes",
                result.output,
            )
            self.assertFalse(output.exists())

    def test_harbor_task_compiler_deploys_explicit_weakness_catalog(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "catalog"
            shutil.copytree(SMOKE_DIR / "build", root / "build")
            (root / "weakness-overlays").mkdir()
            (root / "weakness-overlays" / "proof.txt").write_text("overlay\n")
            range_file = Path(temp) / "range-plan.yaml"
            range_plan = self._convert_primary_to_cve_analog(
                self._three_node_plan()
            )
            range_file.write_text(yaml.safe_dump(range_plan))
            scenario_file = Path(temp) / "scenario.yaml"
            scenario = load_yaml(SMOKE_DIR / "scenario.yaml")
            scenario["schema_version"] = "1.1"
            scenario_file.write_text(yaml.safe_dump(scenario))
            weakness_catalog_file = Path(temp) / "weaknesses.yaml"
            weakness_catalog_file.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": "1.0",
                        "weaknesses": [
                            {
                                "catalog_ref": f"weakness://smoke/{index}",
                                "candidate_ids": [f"candidate-{index}"],
                                "service_catalog_ref": "service://smoke/http",
                                "file_overlays": [
                                    {
                                        "source": "weakness-overlays/proof.txt",
                                        "target": f"/usr/share/nginx/html/proof-{index}.txt",
                                    }
                                ],
                            }
            for index in (1, 2, 3)
                        ],
                    }
                )
            )
            assets = Path(temp) / "assets"
            assets.mkdir()
            (assets / "task.toml").write_text('[task]\nname="smoke"\n')
            (assets / "README.md").write_text("# Smoke task\n")
            output = Path(temp) / "task"
            result = CliRunner().invoke(
                render_harbor_task,
                [
                    "--scenario",
                    str(scenario_file),
                    "--range-plan",
                    str(range_file),
                    "--catalog",
                    str(SMOKE_DIR / "service-catalog.yaml"),
                    "--catalog-root",
                    str(root),
                    "--weakness-catalog",
                    str(weakness_catalog_file),
                    "--task-assets",
                    str(assets),
                    "--output",
                    str(output),
                ],
            )
            self.assertEqual(result.exit_code, 0, result.output)
            generated_dockerfile = (
                output / "environment/build/status-page/Dockerfile.mhbench"
            )
            self.assertTrue(generated_dockerfile.is_file())
            self.assertIn(
                "/usr/share/nginx/html/proof-1.txt",
                generated_dockerfile.read_text(),
            )


if __name__ == "__main__":
    unittest.main()
