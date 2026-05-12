"""Phase 3: Registry Scanner — monitor and scan public Skill registries."""

import json
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone


@dataclass
class RegistrySkill:
    """A skill discovered from a public registry."""
    name: str
    version: str
    source_url: str
    author: str = "unknown"
    description: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trust_score: int = 0
    scan_result: Optional[dict] = None


class RegistryScanner:
    """Discovers and scans skills from public registries."""

    def __init__(self, db_path: str = ".agent-skills/registry"):
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        self.db_file = self.db_path / "skills.json"
        self._load_db()

    def _load_db(self):
        if self.db_file.exists():
            self.db = json.loads(self.db_file.read_text())
        else:
            self.db = {"skills": [], "malicious": [], "last_sync": None}

    def _save_db(self):
        self.db_file.write_text(json.dumps(self.db, indent=2))

    def discover_from_github(self, query: str = "SKILL.md", max_results: int = 10) -> list[dict]:
        """Discover skills from GitHub code search (requires GITHUB_TOKEN)."""
        import os
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("SKILL_SCANNER_GITHUB_TOKEN")
        if not token:
            return []

        import urllib.request
        import urllib.parse

        url = (
            f"https://api.github.com/search/code"
            f"?q={urllib.parse.quote(query)}+in:path+filename:SKILL.md"
            f"&per_page={max_results}"
        )
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"token {token}")
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "skill-scanner")

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                results = []
                for item in data.get("items", []):
                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    results.append({
                        "repo": repo,
                        "path": path,
                        "url": f"https://github.com/{repo}/blob/main/{path}",
                        "raw_url": f"https://raw.githubusercontent.com/{repo}/main/{path}",
                    })
                return results
        except Exception:
            return []

    def scan_registry_skill(self, raw_url: str) -> Optional[dict]:
        """Fetch and scan a skill from a raw URL."""
        import urllib.request
        import urllib.parse

        # URL safety checks: only allow known code hosts
        parsed = urllib.parse.urlparse(raw_url)
        allowed_domains = {
            "raw.githubusercontent.com", "github.com",
            "githubusercontent.com", "clawhub.com",
        }
        if parsed.hostname not in allowed_domains:
            return None
        # Block private/internal IP ranges
        import socket
        try:
            ip = socket.gethostbyname(parsed.hostname)
            private_prefixes = ("10.", "172.16.", "192.168.", "127.", "169.254.")
            if any(ip.startswith(p) for p in private_prefixes):
                return None
        except socket.gaierror:
            return None

        try:
            req = urllib.request.Request(raw_url)
            req.add_header("User-Agent", "skill-scanner")
            with urllib.request.urlopen(req, timeout=10) as resp:
                # Limit response size
                MAX_BYTES = 1 * 1024 * 1024  # 1MB
                content = resp.read(MAX_BYTES).decode("utf-8", errors="replace")
        except Exception:
            return None

        # Save to temp dir and scan
        import tempfile
        import shutil

        tmpdir = tempfile.mkdtemp(prefix="skill-scanner-registry-")
        try:
            skill_dir = Path(tmpdir) / "skill"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(content)

            from skill_scanner.engine import scan_skill
            result = scan_skill(str(skill_dir))
            return result
        except Exception:
            return None
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def compute_trust_score(self, skill: dict, scan_result: dict) -> int:
        """Compute a trust score (0-100) for a skill based on scan results + community signals."""
        score = 100

        # Deduct for security findings
        score -= scan_result.get("critical", 0) * 35
        score -= scan_result.get("warnings", 0) * 10

        # Deduct for missing metadata
        if skill.get("author") == "unknown":
            score -= 10
        if not skill.get("description"):
            score -= 5

        # Bonus for being in registry DB with history
        existing = self.find_in_db(skill.get("name", ""))
        if existing and existing.get("trust_score", 0) > 50:
            score += 5

        return max(0, min(100, score))

    def find_in_db(self, name: str) -> Optional[dict]:
        """Find a skill in the local registry database."""
        for s in self.db["skills"]:
            if s.get("name") == name:
                return s
        return None

    def add_to_db(self, skill: dict, scan_result: dict):
        """Add or update a skill in the local registry database."""
        existing = self.find_in_db(skill.get("name", ""))
        if existing:
            idx = self.db["skills"].index(existing)
            self.db["skills"][idx] = {**existing, **skill, "scan_result": scan_result}
        else:
            self.db["skills"].append({**skill, "scan_result": scan_result})
        self._save_db()

    def report_malicious(self, skill_name: str, reason: str):
        """Report a skill as malicious to the community database."""
        report = {
            "skill_name": skill_name,
            "reason": reason,
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }
        self.db["malicious"].append(report)
        self._save_db()

    def is_known_malicious(self, skill_name: str) -> bool:
        """Check if a skill is in the known malicious database."""
        return any(m["skill_name"] == skill_name for m in self.db["malicious"])

    def sync_stats(self) -> dict:
        """Return registry statistics."""
        return {
            "total_skills": len(self.db["skills"]),
            "malicious_reports": len(self.db["malicious"]),
            "last_sync": self.db.get("last_sync"),
        }
