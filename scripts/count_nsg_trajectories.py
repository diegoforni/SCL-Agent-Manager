#!/usr/bin/env python3
"""Count NSG State Creator trajectory states and actions for a run."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


DEFAULT_OUTPUTS = Path(os.environ.get("OUTPUTS_DIR", "/opt/Agents/Experiments"))
DEFAULT_TOPOLOGIES = Path(
    os.environ.get(
        "TOPOLOGIES_DIR",
        Path(__file__).resolve().parents[2] / "SCL-Network-Topology-Creator/data/topologies",
    )
)


def active_run(outputs: Path) -> str:
    marker = outputs / ".current_run"
    try:
        run_id = marker.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"Cannot read active-run marker {marker}: {exc}") from exc
    if not run_id:
        raise SystemExit(f"Active-run marker is empty: {marker}")
    return run_id


def load_assignments(topology_file: Path) -> dict[str, list[str]]:
    try:
        topology = json.loads(topology_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read topology {topology_file}: {exc}") from exc

    assignments: dict[str, list[str]] = {}
    for network in topology.get("networks", []):
        network_id = network.get("id")
        for host in network.get("hosts", []):
            agents = [str(agent) for agent in host.get("agents", []) if agent]
            if network_id and host.get("id") and agents:
                assignments[f"{network_id}-{host['id']}"] = agents
    return assignments


def count_files(path: Path, pattern: str) -> int:
    return sum(1 for item in path.glob(pattern) if item.is_file()) if path.is_dir() else 0


def collect(run_dir: Path, assignments: dict[str, list[str]]) -> list[dict[str, object]]:
    observer = run_dir / "observer"
    if not observer.is_dir():
        raise SystemExit(f"Observer results directory not found: {observer}")

    rows = []
    for service_dir in sorted(path for path in observer.iterdir() if path.is_dir()):
        states_dir = service_dir / "trajectory/states"
        states = (
            sum(1 for path in states_dir.glob("state-*") if path.is_dir())
            if states_dir.is_dir()
            else 0
        )
        actions = count_files(service_dir / "trajectory/actions", "*.json")
        sequence_file = service_dir / "trajectory/sequence.jsonl"
        try:
            sequence_records = sum(1 for line in sequence_file.open(encoding="utf-8") if line.strip())
        except OSError:
            sequence_records = 0
        rows.append(
            {
                "service": service_dir.name,
                "agents": assignments.get(service_dir.name, []),
                "states": states,
                "actions": actions,
                "sequence_records": sequence_records,
            }
        )
    return rows


def totals(rows: list[dict[str, object]]) -> dict[str, int]:
    return {
        "containers": len(rows),
        "states": sum(int(row["states"]) for row in rows),
        "actions": sum(int(row["actions"]) for row in rows),
        "sequence_records": sum(int(row["sequence_records"]) for row in rows),
    }


def render_table(rows: list[dict[str, object]]) -> str:
    headers = ("Service", "Agent(s)", "States", "Actions", "Sequence")
    values = [
        (
            str(row["service"]),
            ", ".join(row["agents"]) or "—",
            f"{int(row['states']):,}",
            f"{int(row['actions']):,}",
            f"{int(row['sequence_records']):,}",
        )
        for row in rows
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in values))
        for index in range(len(headers))
    ]

    def border(left: str, middle: str, right: str) -> str:
        return left + middle.join("─" * (width + 2) for width in widths) + right

    def cells(row: tuple[str, ...], numeric: bool = False) -> str:
        rendered = []
        for index, value in enumerate(row):
            align = ">" if numeric and index >= 2 else "<"
            rendered.append(f" {value:{align}{widths[index]}} ")
        return "│" + "│".join(rendered) + "│"

    lines = [border("┌", "┬", "┐"), cells(headers), border("├", "┼", "┤")]
    lines.extend(cells(row, numeric=True) for row in values)
    lines.append(border("└", "┴", "┘"))
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id", nargs="?", help="Run directory name; defaults to .current_run")
    parser.add_argument("--outputs-root", type=Path, default=DEFAULT_OUTPUTS)
    parser.add_argument("--topology", type=Path, help="Explicit topology.json used to identify agents")
    parser.add_argument("--agents-only", action="store_true", help="Show only agent-enabled services")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable JSON instead of the console table")
    args = parser.parse_args()

    run_id = args.run_id or active_run(args.outputs_root)
    run_dir = args.outputs_root / run_id
    topology_file = args.topology or DEFAULT_TOPOLOGIES / run_id / "topology.json"
    assignments = load_assignments(topology_file)
    all_rows = collect(run_dir, assignments)
    shown_rows = [row for row in all_rows if row["agents"]] if args.agents_only else all_rows
    agent_rows = [row for row in all_rows if row["agents"]]

    agent = totals(agent_rows)
    overall = totals(all_rows)
    if args.as_json:
        print(
            json.dumps(
                {
                    "run_id": run_id,
                    "run_dir": str(run_dir),
                    "topology_file": str(topology_file),
                    "services": shown_rows,
                    "agent_totals": agent,
                    "all_totals": overall,
                },
                indent=2,
            )
        )
        return

    print(f"\nNSG trajectory report: {run_id}")
    print(f"Results directory: {run_dir}\n")
    print(render_table(shown_rows))
    print("\nSummary")
    print(f"  Agent-enabled containers : {agent['containers']}")
    print(f"  Agent states             : {agent['states']:,}")
    print(f"  Agent actions            : {agent['actions']:,}")
    print(f"  All monitored containers : {overall['containers']}")
    print(f"  All states               : {overall['states']:,}")
    print(f"  All actions              : {overall['actions']:,}\n")


if __name__ == "__main__":
    main()
