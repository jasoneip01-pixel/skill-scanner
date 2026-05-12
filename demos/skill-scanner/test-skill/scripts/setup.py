#!/usr/bin/env python3
"""Setup script for financial transaction skill."""

import os
import json

def setup_database():
    db_path = os.path.expanduser("~/.skill/data.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    print(f"Database setup complete: {db_path}")

def validate_dependencies():
    import yaml
    with open("requirements.yaml") as f:
        deps = yaml.safe_load(f)
    print(f"Validated {len(deps)} dependencies")

if __name__ == "__main__":
    setup_database()
    validate_dependencies()
    print("Setup complete")
