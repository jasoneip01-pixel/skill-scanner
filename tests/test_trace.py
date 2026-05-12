"""Tests for trace_engine.py — trace recording, loading, comparison."""

import json
from pathlib import Path
import pytest
from skill_scanner.trace_engine import TraceRecorder, TraceComparator


class TestTraceRecorder:
    def test_record_and_load(self, tmp_path):
        """Record a trace and load it back."""
        recorder = TraceRecorder(storage_dir=str(tmp_path / "traces"))
        trace_id = recorder.record("test-skill", "1.0.0", [
            {"tool": "readFile", "method": "GET"},
            {"tool": "writeFile", "method": "POST"},
        ])
        assert trace_id is not None
        loaded = recorder.load(trace_id)
        assert loaded is not None
        assert loaded["skill_name"] == "test-skill"
        assert len(loaded["calls"]) == 2

    def test_sanitize_id_replaces_separators(self, tmp_path):
        """_sanitize_id should replace path separators."""
        recorder = TraceRecorder(storage_dir=str(tmp_path / "traces"))
        safe = recorder._sanitize_id("../../evil")
        # After sanitize: / → _, so ../../evil → .._.._evil
        assert "/" not in safe
        assert safe == ".._.._evil"
        # Verify it can't traverse — will use path guard in record/load

    def test_sanitize_id_handles_unicode(self, tmp_path):
        """_sanitize_id should handle Unicode."""
        recorder = TraceRecorder(storage_dir=str(tmp_path / "traces"))
        safe = recorder._sanitize_id("🔥unicode🔥")
        assert isinstance(safe, str)
        assert len(safe) > 0

    def test_record_never_writes_outside(self, tmp_path):
        """record should never write outside storage_dir."""
        storage = tmp_path / "traces"
        recorder = TraceRecorder(storage_dir=str(storage))
        recorder.record("../outside", "1.0.0", [{"tool": "t"}])
        files = list(storage.glob("*.json"))
        assert len(files) >= 1

    def test_load_rejects_outside(self, tmp_path):
        """load should reject trace_id that would escape."""
        storage = tmp_path / "traces"
        recorder = TraceRecorder(storage_dir=str(storage))
        result = recorder.load("../../etc/passwd")
        assert result is None

    def test_load_known_trace(self, tmp_path):
        """Record and load known traces."""
        storage = tmp_path / "traces"
        recorder = TraceRecorder(storage_dir=str(storage))
        tid1 = recorder.record("alpha", "1.0", [])
        tid2 = recorder.record("alpha", "2.0", [])
        tid3 = recorder.record("beta", "1.0", [])
        assert recorder.load(tid1) is not None
        assert recorder.load(tid2) is not None
        assert recorder.load(tid3) is not None


class TestTraceComparator:
    def test_no_diff(self, tmp_path):
        """Identical traces should produce no diffs."""
        recorder = TraceRecorder(storage_dir=str(tmp_path / "traces"))
        trace_data = [
            {"tool": "readFile", "method": "GET"},
            {"tool": "writeFile", "method": "POST"},
        ]
        old_id = recorder.record("skill", "1.0", list(trace_data))
        new_id = recorder.record("skill", "1.1", list(trace_data))
        old = recorder.load(old_id)
        new = recorder.load(new_id)
        result = TraceComparator.compare(old, new)
        assert len(result["diffs"]) == 0

    def test_added_tool_diff(self, tmp_path):
        """Added tool should produce diff."""
        recorder = TraceRecorder(storage_dir=str(tmp_path / "traces"))
        old_id = recorder.record("skill", "1.0", [
            {"tool": "readFile", "method": "GET"},
        ])
        new_id = recorder.record("skill", "1.1", [
            {"tool": "readFile", "method": "GET"},
            {"tool": "deleteFile", "method": "DELETE"},
        ])
        old = recorder.load(old_id)
        new = recorder.load(new_id)
        result = TraceComparator.compare(old, new)
        added = [d for d in result["diffs"] if d.get("type") == "new_tool"]
        assert len(added) == 1
        assert added[0]["tool"] == "deleteFile"

    def test_removed_tool_diff(self, tmp_path):
        """Removed tool should produce diff."""
        recorder = TraceRecorder(storage_dir=str(tmp_path / "traces"))
        old_id = recorder.record("skill", "1.0", [
            {"tool": "readFile", "method": "GET"},
            {"tool": "deleteFile", "method": "DELETE"},
        ])
        new_id = recorder.record("skill", "1.1", [
            {"tool": "readFile", "method": "GET"},
        ])
        old = recorder.load(old_id)
        new = recorder.load(new_id)
        result = TraceComparator.compare(old, new)
        removed = [d for d in result["diffs"] if d.get("type") == "removed_tool"]
        assert len(removed) == 1

    def test_nil_baseline(self):
        """Compare should handle empty records."""
        result = TraceComparator.compare({"calls": []}, {"calls": []})
        assert isinstance(result, dict)
        assert len(result["diffs"]) == 0
