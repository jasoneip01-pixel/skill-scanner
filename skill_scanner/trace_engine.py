"""Phase 2: Trace Replay Engine — record and compare Agent tool call traces.

Detects capability drift by comparing actual execution traces against baseline.
"""

import json
import re
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone


_SAFE_ID = re.compile(r'^[A-Za-z0-9._-]+$')


class TraceRecorder:
    """Records Agent tool call traces for baseline comparison."""

    def __init__(self, storage_dir: str = ".agent-skills/traces"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.storage_dir = self.storage_dir.resolve()

    def _sanitize_id(self, s: str) -> str:
        """Sanitize a string for safe use in filenames."""
        return re.sub(r'[^A-Za-z0-9._-]', '_', s)[:128]

    def record(self, skill_name: str, version: str, trace: list[dict]) -> str:
        """Record a trace as baseline. Returns trace ID."""
        safe_name = self._sanitize_id(skill_name)
        safe_ver = self._sanitize_id(version) if version else "0.0.0"
        ts = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        trace_id = f"{safe_name}-{safe_ver}-{ts}"
        record = {
            "trace_id": trace_id,
            "skill_name": safe_name,
            "version": safe_ver,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "calls": trace,
        }
        path = (self.storage_dir / f"{trace_id}.json").resolve()
        # Guard: path must stay under storage_dir
        try:
            path.relative_to(self.storage_dir)
        except ValueError:
            raise ValueError(f"Trace path escape blocked: {path}")
        path.write_text(json.dumps(record, indent=2))
        return trace_id

    def load(self, trace_id: str) -> Optional[dict]:
        """Load a recorded trace by ID."""
        safe_id = self._sanitize_id(trace_id)
        path = (self.storage_dir / f"{safe_id}.json").resolve()
        try:
            path.relative_to(self.storage_dir)
        except ValueError:
            return None
        if path.exists():
            return json.loads(path.read_text())
        # Try fuzzy match (latest for skill)
        prefix = safe_id.rsplit("-", 1)[0]
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
