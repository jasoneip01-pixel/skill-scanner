"""Phase 2: Trace Replay Engine — record and compare Agent tool call traces.

Detects capability drift by comparing actual execution traces against baseline.
"""

import json
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone


class TraceRecorder:
    """Records Agent tool call traces for baseline comparison."""

    def __init__(self, storage_dir: str = ".agent-skills/traces"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def record(self, skill_name: str, version: str, trace: list[dict]) -> str:
        """Record a trace as baseline. Returns trace ID."""
        trace_id = f"{skill_name}-{version}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        record = {
            "trace_id": trace_id,
            "skill_name": skill_name,
            "version": version,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "calls": trace,
        }
        path = self.storage_dir / f"{trace_id}.json"
        path.write_text(json.dumps(record, indent=2))
        return trace_id

    def load(self, trace_id: str) -> Optional[dict]:
        """Load a recorded trace by ID."""
        path = self.storage_dir / f"{trace_id}.json"
        if path.exists():
            return json.loads(path.read_text())
        # Try fuzzy match (latest for skill)
        prefix = trace_id.rsplit("-", 1)[0]
        matches = sorted(self.storage_dir.glob(f"{prefix}*.json"))
        if matches:
            return json.loads(matches[-1].read_text())
        return None


class TraceComparator:
    """Compare two traces to detect capability drift."""

    @staticmethod
    def compare(baseline: dict, current: dict) -> dict:
        """Compare current trace against baseline. Returns diff report."""
        baseline_calls = baseline.get("calls", [])
        current_calls = current.get("calls", [])

        baseline_tools = {c.get("tool"): c for c in baseline_calls}
        current_tools = {c.get("tool"): c for c in current_calls}

        added_tools = set(current_tools.keys()) - set(baseline_tools.keys())
        removed_tools = set(baseline_tools.keys()) - set(current_tools.keys())
        common_tools = set(current_tools.keys()) & set(baseline_tools.keys())

        diffs = []

        # New tools appeared
        for tool in added_tools:
            diffs.append({
                "type": "new_tool",
                "tool": tool,
                "severity": "warning",
                "detail": f"Tool '{tool}' was not present in baseline trace",
            })

        # Tools removed
        for tool in removed_tools:
            diffs.append({
                "type": "removed_tool",
                "tool": tool,
                "severity": "info",
                "detail": f"Tool '{tool}' present in baseline but not in current trace",
            })

        # Parameter changes in common tools
        for tool in common_tools:
            b = baseline_tools[tool]
            c = current_tools[tool]

            b_params = set(b.get("params", {}).keys()) if isinstance(b.get("params"), dict) else set()
            c_params = set(c.get("params", {}).keys()) if isinstance(c.get("params"), dict) else set()

            new_params = c_params - b_params
            if new_params:
                diffs.append({
                    "type": "new_params",
                    "tool": tool,
                    "severity": "warning",
                    "detail": f"Tool '{tool}' gained new parameters: {', '.join(sorted(new_params))}",
                })

            # Check HTTP method changes
            b_method = b.get("method", "").upper()
            c_method = c.get("method", "").upper()
            if b_method != c_method and c_method in ("POST", "PUT", "DELETE"):
                diffs.append({
                    "type": "method_change",
                    "tool": tool,
                    "severity": "critical",
                    "detail": f"Tool '{tool}' HTTP method changed from {b_method} to {c_method}",
                })

        high_severity = [d for d in diffs if d["severity"] == "critical"]
        return {
            "baseline_trace_id": baseline.get("trace_id"),
            "current_trace_id": current.get("trace_id"),
            "diffs": diffs,
            "new_tools": sorted(added_tools),
            "removed_tools": sorted(removed_tools),
            "blocked": len(high_severity) > 0,
            "summary": f"{len(added_tools)} new tools, {len(removed_tools)} removed, {len(diffs)} total changes",
        }
