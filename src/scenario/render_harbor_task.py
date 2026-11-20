"""Compile a reviewed scenario/range pair and task assets into a Harbor task."""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

import click

from .compose_backend import (
    ServiceCatalog,
    WeaknessCatalog,
    load_bundle,
    load_yaml,
    render_compose,
)


def _entry_instruction(bundle) -> str:
    entry = bundle.range.entry_state
    service = next(
        service for service in bundle.range.services if service.id == entry.service_id
    )
    endpoint = entry.endpoint
    if endpoint is None:
        port = service.ports[0] if service.ports else 80
        endpoint = f"http://{service.id}:{port}/"

    lines = [
        "# Access",
        "",
        f"The service is available at `{endpoint}`.",
    ]
    if entry.credentials:
        lines.extend(["", "Use these credentials:", ""])
        lines.extend(
            f"- {name}: `{value}`"
            for name, value in entry.credentials.items()
        )
    if bundle.range.agent and bundle.range.agent.tools:
        lines.extend(
            [
                "",
                "The shell includes: "
                + ", ".join(f"`{tool}`" for tool in bundle.range.agent.tools)
                + ".",
            ]
        )
    return "\n".join(lines) + "\n"


def _copy_task_assets(assets_dir: Path, output_dir: Path) -> None:
    task_file = assets_dir / "task.toml"
    if not task_file.is_file():
        raise ValueError(f"required Harbor task asset is missing: {task_file}")
    try:
        task_config = tomllib.loads(task_file.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid Harbor task TOML: {exc}") from exc
    if _contains_public_network_mode(task_config):
        raise ValueError(
            "network_mode = \"public\" is prohibited; use a closed "
            "network policy and explicitly test required service reachability"
        )

    for name in ("task.toml", "README.md"):
        source = assets_dir / name
        if not source.is_file():
            raise ValueError(f"required Harbor task asset is missing: {source}")
        shutil.copy2(source, output_dir / name)

    for name in ("tests", "solution", "hint"):
        source = assets_dir / name
        if not source.exists():
            continue
        if not source.is_dir():
            raise ValueError(f"Harbor task asset must be a directory: {source}")
        destination = output_dir / name
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)


def _contains_public_network_mode(value) -> bool:
    """Reject public network policy wherever Harbor task assets declare it."""
    if isinstance(value, dict):
        return any(
            (key == "network_mode" and item == "public")
            or _contains_public_network_mode(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_public_network_mode(item) for item in value)
    return False


def _require_benchmark_ready(range_plan) -> None:
    """Prevent an incomplete scenario preview from being packaged as a task."""
    if any(path.status == "approved" for path in range_plan.candidate_paths):
        return
    raise ValueError(
        "cannot package a benchmark-ready Harbor task without an approved "
        "candidate path containing at least three deployed weakness nodes; "
        "use --draft-preview only for environment/compiler smoke tests"
    )


@click.command()
@click.option(
    "--scenario",
    "scenario_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--range-plan",
    "range_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--catalog",
    "catalog_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--catalog-root",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--weakness-catalog",
    "weakness_catalog_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Reviewed catalog required when the range plan selects weaknesses.",
)
@click.option(
    "--task-assets",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--output",
    "output_dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
)
@click.option(
    "--draft-preview",
    is_flag=True,
    help=(
        "Allow packaging an incomplete scenario for environment/compiler "
        "smoke tests; this is not a benchmark-ready task."
    ),
)
def main(
    scenario_file: Path,
    range_file: Path,
    catalog_file: Path,
    catalog_root: Path,
    weakness_catalog_file: Path | None,
    task_assets: Path,
    output_dir: Path,
    draft_preview: bool,
) -> None:
    """Write an environment plus Harbor task metadata and authored grader assets."""
    try:
        bundle = load_bundle(scenario_file, range_file)
        if not draft_preview:
            _require_benchmark_ready(bundle.range)
        catalog = ServiceCatalog.model_validate(load_yaml(catalog_file))
        weakness_catalog = (
            WeaknessCatalog.model_validate(load_yaml(weakness_catalog_file))
            if weakness_catalog_file
            else None
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        environment_dir = output_dir / "environment"
        render_compose(
            bundle,
            catalog,
            catalog_root=catalog_root,
            output_dir=environment_dir,
            weakness_catalog=weakness_catalog,
        )
        _copy_task_assets(task_assets, output_dir)
        (output_dir / "instruction.md").write_text(_entry_instruction(bundle))
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if draft_preview:
        click.echo(
            "Rendered Harbor task draft preview (NOT benchmark-ready): "
            f"{output_dir}"
        )
    else:
        click.echo(f"Rendered benchmark-ready Harbor task: {output_dir}")


if __name__ == "__main__":
    main()
