from __future__ import annotations

import importlib
from pathlib import Path
from typing import Generator

import yaml

from core.finding import RuleMetadata
from core.rule import Rule


def _rules_from_config(config: dict) -> Generator[Rule, None, None]:
    for entry in config.get("rules", []):
        if not entry.get("enabled", True):
            continue
        metadata = RuleMetadata(
            id=entry["id"],
            name=entry["name"],
            version=entry["version"],
            severity=entry["severity"],
            confidence=float(entry["confidence"]),
            explanation_template=entry["explanation_template"],
            enabled=entry.get("enabled", True),
        )
        module = importlib.import_module(entry["module"])
        cls = getattr(module, entry["class"])
        yield cls(metadata=metadata)


def load_rules(config_path: Path) -> list[Rule]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return list(_rules_from_config(config))
