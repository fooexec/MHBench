"""Render a validated scenario/range pair as a portable Compose environment.

Service templates and explicitly selected weaknesses resolve through separate
reviewed catalogs. Weakness deployment supports deterministic file overlays on
build-backed services and digest-verified image pins on prebuilt services;
unsupported or unresolved weaknesses fail closed rather than being silently
omitted.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .spec import RangePlan, ScenarioBundle, ScenarioPlan

_DOCKERFILE_STAGE_PATTERN = re.compile(
    r"^\s*FROM\b.*\s+AS\s+([^\s#]+)(?:\s+#.*)?$",
    re.IGNORECASE,
)


class ServiceTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    catalog_ref: str
    delivery: Literal["image", "build"]
    image: str | None = None
    context: str | None = None
    dockerfile: str = "Dockerfile"
    build_target: str | None = None
    mem_limit: str | None = None
    default_expose: list[int] = Field(default_factory=list)
    healthcheck: list[str] | None = None
    healthcheck_start_period: str = "10s"

    @model_validator(mode="after")
    def validate_delivery(self) -> "ServiceTemplate":
        if self.mem_limit is not None and not re.fullmatch(
            r"\d+(?:\.\d+)?(?:b|k|m|g|kb|mb|gb)?",
            self.mem_limit.strip(),
            re.IGNORECASE,
        ):
            raise ValueError("mem_limit must be a Docker Compose memory size")
        if not re.fullmatch(
            r"\d+(?:\.\d+)?(?:ns|us|ms|s|m|h)",
            self.healthcheck_start_period,
        ):
            raise ValueError("healthcheck_start_period must be a Compose duration")
        if self.build_target is not None and not self.build_target.strip():
            raise ValueError("build_target must be a non-empty Dockerfile stage")
        if self.delivery == "image" and (
            not self.image or self.context or self.build_target
        ):
            raise ValueError(
                "image delivery requires image and forbids context/build_target"
            )
        if self.delivery == "build" and (not self.context or self.image):
            raise ValueError("build delivery requires context and forbids image")
        return self


class ServiceCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    services: list[ServiceTemplate] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_refs(self) -> "ServiceCatalog":
        refs = [entry.catalog_ref for entry in self.services]
        if len(refs) != len(set(refs)):
            raise ValueError("service catalog_ref values must be unique")
        return self

    def by_ref(self) -> dict[str, ServiceTemplate]:
        return {entry.catalog_ref: entry for entry in self.services}


class FileOverlay(BaseModel):
    """A reviewed file replacement installed into one service image."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str


class WeaknessTemplate(BaseModel):
    """Deterministic deployment adapter for one reviewed weakness candidate."""

    model_config = ConfigDict(extra="forbid")

    catalog_ref: str
    candidate_ids: list[str] = Field(min_length=1)
    service_catalog_ref: str
    deployment: Literal["file_overlay", "pinned_image"] = "file_overlay"
    file_overlays: list[FileOverlay] = Field(default_factory=list)
    image_digest: str | None = None

    @model_validator(mode="after")
    def validate_deployment(self) -> "WeaknessTemplate":
        if len(self.candidate_ids) != len(set(self.candidate_ids)):
            raise ValueError(
                f"weakness template {self.catalog_ref} repeats candidate IDs"
            )
        if self.deployment == "file_overlay":
            if not self.file_overlays:
                raise ValueError(
                    f"weakness template {self.catalog_ref} file_overlay "
                    "deployment requires at least one overlay"
                )
            if self.image_digest is not None:
                raise ValueError(
                    f"weakness template {self.catalog_ref} file_overlay "
                    "deployment cannot declare image_digest"
                )
        else:
            if self.file_overlays:
                raise ValueError(
                    f"weakness template {self.catalog_ref} pinned_image "
                    "deployment cannot declare file_overlays"
                )
            if not self.image_digest or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", self.image_digest
            ):
                raise ValueError(
                    f"weakness template {self.catalog_ref} pinned_image "
                    "deployment requires a lowercase sha256 image_digest"
                )
        for overlay in self.file_overlays:
            source = PurePosixPath(overlay.source)
            target = PurePosixPath(overlay.target)
            if (
                source.is_absolute()
                or not source.parts
                or ".." in source.parts
            ):
                raise ValueError(
                    f"weakness template {self.catalog_ref} overlay source "
                    "must be a relative path without '..'"
                )
            if (
                not target.is_absolute()
                or ".." in target.parts
                or target == PurePosixPath("/")
            ):
                raise ValueError(
                    f"weakness template {self.catalog_ref} overlay target "
                    "must be an absolute container file path"
                )
        return self


class WeaknessCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    weaknesses: list[WeaknessTemplate] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_refs(self) -> "WeaknessCatalog":
        refs = [entry.catalog_ref for entry in self.weaknesses]
        if len(refs) != len(set(refs)):
            raise ValueError("weakness catalog_ref values must be unique")
        return self

    def by_ref(self) -> dict[str, WeaknessTemplate]:
        return {entry.catalog_ref: entry for entry in self.weaknesses}


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return value


def _copy_build_context(
    template: ServiceTemplate,
    catalog_root: Path,
    output_dir: Path,
    service_id: str,
) -> dict[str, str]:
    context_rel = PurePosixPath(template.context or "")
    if context_rel.is_absolute() or ".." in context_rel.parts:
        raise ValueError(
            f"service template {template.catalog_ref} context must be "
            "a relative path without '..'"
        )
    dockerfile_rel = PurePosixPath(template.dockerfile)
    if dockerfile_rel.is_absolute() or ".." in dockerfile_rel.parts:
        raise ValueError(
            f"service template {template.catalog_ref} Dockerfile must "
            "be relative to its context"
        )
    source = (catalog_root / Path(*context_rel.parts)).resolve()
    root = catalog_root.resolve()
    if not source.is_relative_to(root) or not source.is_dir():
        raise ValueError(
            f"build context for {template.catalog_ref} is missing or "
            "escapes the catalog root"
        )
    dockerfile_source = source / Path(*dockerfile_rel.parts)
    if (
        not dockerfile_source.resolve().is_relative_to(source)
        or not dockerfile_source.is_file()
    ):
        raise ValueError(
            f"Dockerfile for {template.catalog_ref} does not exist"
        )
    if template.build_target and not any(
        (match := _DOCKERFILE_STAGE_PATTERN.match(line))
        and match.group(1) == template.build_target
        for line in dockerfile_source.read_text().splitlines()
    ):
        raise ValueError(
            f"build_target {template.build_target!r} for "
            f"{template.catalog_ref} does not name a Dockerfile stage"
        )
    for item in source.rglob("*"):
        if item.is_symlink() and not item.resolve().is_relative_to(source):
            raise ValueError(
                f"build context for {template.catalog_ref} contains a "
                "symlink that escapes its context"
            )
    destination = output_dir / "build" / service_id
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    return {
        "context": f"./build/{service_id}",
        "dockerfile": template.dockerfile,
    }


def _install_harbor_agent_dockerfile(
    template: ServiceTemplate,
    catalog_root: Path,
    output_dir: Path,
) -> None:
    """Install the attacker image recipe at Harbor's required environment/Dockerfile."""
    if template.delivery != "build":
        raise ValueError("Harbor agent environment must use a build template")
    context_rel = PurePosixPath(template.context or "")
    dockerfile_rel = PurePosixPath(template.dockerfile)
    if (
        context_rel.is_absolute()
        or ".." in context_rel.parts
        or dockerfile_rel.is_absolute()
        or ".." in dockerfile_rel.parts
    ):
        raise ValueError("agent build context and Dockerfile must stay in catalog root")
    source = (catalog_root / Path(*context_rel.parts)).resolve()
    root = catalog_root.resolve()
    dockerfile_source = source / Path(*dockerfile_rel.parts)
    if (
        not source.is_relative_to(root)
        or not source.is_dir()
        or not dockerfile_source.resolve().is_relative_to(source)
        or not dockerfile_source.is_file()
    ):
        raise ValueError("Harbor agent Dockerfile/context is missing or escapes catalog root")
    for item in source.rglob("*"):
        if item.is_symlink() and not item.resolve().is_relative_to(source):
            raise ValueError("Harbor agent context contains a symlink outside its root")
    payload = [item for item in source.iterdir() if item.name != template.dockerfile]
    if payload:
        raise ValueError(
            "agent Dockerfile context must currently contain only its Dockerfile; "
            "add a declared assets mechanism before using extra files"
        )
    shutil.copy2(dockerfile_source, output_dir / "Dockerfile")


def render_compose(
    bundle: ScenarioBundle,
    catalog: ServiceCatalog,
    catalog_root: Path,
    output_dir: Path,
    weakness_catalog: WeaknessCatalog | None = None,
) -> Path:
    """Render Compose, service contexts, and explicitly selected file overlays."""
    if bundle.range.weaknesses and weakness_catalog is None:
        raise ValueError(
            "weakness catalog deployment requires a reviewed weakness catalog"
        )
    templates = catalog.by_ref()
    weakness_templates = (
        weakness_catalog.by_ref() if weakness_catalog is not None else {}
    )
    selected_by_service: dict[str, list[tuple[WeaknessTemplate, str]]] = {}
    candidate_by_id = {
        candidate.id: candidate for candidate in bundle.range.weakness_candidates
    }
    service_by_id = {service.id: service for service in bundle.range.services}
    overlay_targets: dict[str, set[str]] = {}
    for weakness in bundle.range.weaknesses:
        candidate = candidate_by_id[weakness.candidate_id]
        weakness_template = weakness_templates.get(weakness.catalog_ref)
        if weakness_template is None:
            raise ValueError(
                f"weakness {weakness.id} has unresolved catalog_ref "
                f"{weakness.catalog_ref!r}"
            )
        if candidate.id not in weakness_template.candidate_ids:
            raise ValueError(
                f"weakness template {weakness_template.catalog_ref} does not "
                f"declare candidate {candidate.id}"
            )
        service_instance = service_by_id[weakness.service_id]
        if service_instance.catalog_ref != weakness_template.service_catalog_ref:
            raise ValueError(
                f"weakness template {weakness_template.catalog_ref} requires "
                f"service template {weakness_template.service_catalog_ref}, "
                f"not {service_instance.catalog_ref}"
            )
        service_template = templates.get(service_instance.catalog_ref)
        if service_template is None:
            raise ValueError(
                f"service {service_instance.id} has unresolved catalog_ref "
                f"{service_instance.catalog_ref!r}"
            )
        if weakness_template.deployment == "file_overlay":
            if service_template.delivery != "build":
                raise ValueError(
                    f"weakness template {weakness_template.catalog_ref} "
                    "file_overlay deployment requires a build-backed service"
                )
            targets = overlay_targets.setdefault(weakness.service_id, set())
            for overlay in weakness_template.file_overlays:
                if overlay.target in targets:
                    raise ValueError(
                        f"multiple selected weaknesses replace "
                        f"{weakness.service_id}:{overlay.target}; define an "
                        "explicit compatible composition instead"
                    )
                targets.add(overlay.target)
        else:
            if service_template.delivery != "image":
                raise ValueError(
                    f"weakness template {weakness_template.catalog_ref} "
                    "pinned_image deployment requires an image-backed service"
                )
            declared_digest = (
                service_template.image.rsplit("@", 1)[-1]
                if service_template.image and "@" in service_template.image
                else None
            )
            if declared_digest != weakness_template.image_digest:
                raise ValueError(
                    f"weakness template {weakness_template.catalog_ref} "
                    f"expects image digest {weakness_template.image_digest}, "
                    f"but service template {service_template.catalog_ref} "
                    f"declares {declared_digest or 'no digest'}"
                )
        selected_by_service.setdefault(weakness.service_id, []).append(
            (weakness_template, weakness.id)
        )

    networks = {network.id: network for network in bundle.range.networks}
    attached_networks: dict[str, list[str]] = {
        service.id: [] for service in bundle.range.services
    }
    for attachment in bundle.range.attachments:
        attached_networks[attachment.service_id].append(attachment.network_id)

    compose_services: dict[str, dict] = {}
    output_dir.mkdir(parents=True, exist_ok=True)
    service_instances = {
        instance.id: instance for instance in bundle.range.services
    }
    for instance in bundle.range.services:
        template = templates.get(instance.catalog_ref)
        if template is None:
            raise ValueError(
                f"service {instance.id} has unresolved catalog_ref "
                f"{instance.catalog_ref!r}"
            )
        if template.healthcheck is None:
            raise ValueError(
                f"target service {instance.id} has no functional healthcheck "
                f"in service template {template.catalog_ref}"
            )
        service: dict = {}
        service["restart"] = "unless-stopped"
        if template.mem_limit:
            service["mem_limit"] = template.mem_limit
        if template.delivery == "image":
            service["image"] = template.image
        else:
            service["build"] = _copy_build_context(
                template, catalog_root, output_dir, instance.id
            )
            if template.build_target:
                service["build"]["target"] = template.build_target
            selected = selected_by_service.get(instance.id, [])
            if selected and any(
                template.deployment == "file_overlay"
                for template, _ in selected
            ):
                service["build"]["dockerfile"] = _install_weakness_overlays(
                    [
                        (template, weakness_id)
                        for template, weakness_id in selected
                        if template.deployment == "file_overlay"
                    ],
                    catalog_root,
                    output_dir / "build" / instance.id,
                    template.dockerfile,
                    template.build_target,
                )
        expose = instance.ports or template.default_expose
        if expose:
            service["expose"] = [str(port) for port in expose]
        if template.healthcheck:
            service["healthcheck"] = {
                "test": template.healthcheck,
                "interval": "10s",
                "timeout": "5s",
                "retries": 5,
                "start_period": template.healthcheck_start_period,
            }
        if instance.depends_on:
            service["depends_on"] = {
                dependency_id: {
                    "condition": (
                        "service_healthy"
                        if templates[
                            service_instances[dependency_id].catalog_ref
                        ].healthcheck
                        else "service_started"
                    )
                }
                for dependency_id in instance.depends_on
            }
        if instance.environment:
            service["environment"] = instance.environment
        if instance.entrypoint is not None:
            service["entrypoint"] = instance.entrypoint
        if instance.command is not None:
            service["command"] = instance.command
        if instance.volume_mounts:
            service["volumes"] = [
                f"{mount.volume_id}:{mount.target}"
                + (":ro" if mount.read_only else "")
                for mount in instance.volume_mounts
            ]
        service["networks"] = attached_networks[instance.id]
        compose_services[instance.id] = service

    if bundle.range.agent:
        agent = bundle.range.agent
        template = templates.get(agent.catalog_ref)
        if template is None:
            raise ValueError(
                f"agent environment has unresolved catalog_ref "
                f"{agent.catalog_ref!r}"
            )
        _install_harbor_agent_dockerfile(template, catalog_root, output_dir)
        agent_service: dict = {}
        agent_service.update(
            {
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "networks": agent.network_ids,
            }
        )
        if template.mem_limit:
            agent_service["mem_limit"] = template.mem_limit
        agent_service["depends_on"] = {
            instance.id: {
                "condition": (
                    "service_healthy"
                    if templates[instance.catalog_ref].healthcheck
                    else "service_started"
                )
            }
            for instance in bundle.range.services
        }
        compose_services["main"] = agent_service

    compose_networks = {
        # Agent-facing and service-private segments have no direct external
        # route. Only an explicitly modeled egress network gets a gateway.
        network.id: {"internal": network.exposure != "egress"}
        for network in bundle.range.networks
    }
    document = {
        "services": compose_services,
        "networks": compose_networks,
    }
    if bundle.range.volumes:
        document["volumes"] = {
            volume.id: {} for volume in bundle.range.volumes
        }
    output_path = output_dir / "docker-compose.yaml"
    output_path.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
    )
    return output_path


def _install_weakness_overlays(
    selected: list[tuple[WeaknessTemplate, str]],
    catalog_root: Path,
    build_context: Path,
    base_dockerfile: str,
    build_target: str | None = None,
) -> str:
    """Copy reviewed overlays into the Dockerfile stage that will be built."""
    root = catalog_root.resolve()
    staged: list[tuple[str, str]] = []
    for template, weakness_id in selected:
        for index, overlay in enumerate(template.file_overlays):
            source_path = root / Path(*PurePosixPath(overlay.source).parts)
            source_cursor = source_path
            while source_cursor != root:
                if source_cursor.is_symlink():
                    raise ValueError(
                        f"overlay source {overlay.source!r} for "
                        f"{template.catalog_ref} traverses a symlink"
                    )
                source_cursor = source_cursor.parent
            source = source_path.resolve()
            if not source.is_relative_to(root) or not source.is_file():
                raise ValueError(
                    f"overlay source {overlay.source!r} for "
                    f"{template.catalog_ref} is missing or escapes catalog root"
                )
            safe_weakness_id = hashlib.sha256(
                weakness_id.encode("utf-8")
            ).hexdigest()[:16]
            relative = (
                Path("_mhbench")
                / "weaknesses"
                / safe_weakness_id
                / f"{index:03d}-{source.name}"
            )
            destination = build_context / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            staged.append((relative.as_posix(), overlay.target))

    original = build_context / base_dockerfile
    dockerfile_text = original.read_text()
    copy_instructions = []
    for source, target in staged:
        copy_instructions.append(
            "COPY " + json.dumps([source, target]) + "\n"
        )
    if build_target is None:
        dockerfile_text += "\n" + "".join(copy_instructions)
    else:
        lines = dockerfile_text.splitlines(keepends=True)
        target_start = next(
            (
                index
                for index, line in enumerate(lines)
                if (match := _DOCKERFILE_STAGE_PATTERN.match(line))
                and match.group(1) == build_target
            ),
            None,
        )
        if target_start is None:
            raise ValueError(
                f"build_target {build_target!r} for "
                f"{base_dockerfile!r} does not name a Dockerfile stage"
            )
        next_stage = next(
            (
                index
                for index in range(target_start + 1, len(lines))
                if re.match(r"^\s*FROM\b", lines[index], re.IGNORECASE)
            ),
            len(lines),
        )
        lines[next_stage:next_stage] = ["\n", *copy_instructions]
        dockerfile_text = "".join(lines)
    generated_name = "Dockerfile.mhbench"
    (build_context / generated_name).write_text(dockerfile_text)
    return generated_name


def load_bundle(scenario_file: Path, range_file: Path) -> ScenarioBundle:
    scenario = ScenarioPlan.model_validate(load_yaml(scenario_file))
    range_plan = RangePlan.model_validate(load_yaml(range_file))
    return ScenarioBundle(scenario=scenario, range=range_plan)
