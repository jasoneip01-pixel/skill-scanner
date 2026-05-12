"""Policy definitions for Skill Scanner."""

from pathlib import Path
import yaml

POLICY_DIR = Path(__file__).parent


def load_policy(name: str) -> dict:
    """Load a named policy (moderate, strict, permissive)."""
    path = POLICY_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Policy not found: {name}")
    return yaml.safe_load(path.read_text())


def list_policies() -> list[str]:
    """List available policy names."""
    return sorted(
        p.stem for p in POLICY_DIR.glob("*.yaml") if not p.name.startswith("_")
    )
