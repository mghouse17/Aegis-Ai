from __future__ import annotations

from pathlib import Path

import yaml

from core.context import AnalysisContext
from core.finding import Finding, RuleMetadata, build_finding
from core.rule import Rule

_DEFAULT_CVE_DB = Path(__file__).parent.parent / "config" / "cve_db.yaml"

# Maps PyPI/npm package name → set of import names used in source code
_IMPORT_ALIASES: dict[str, set[str]] = {
    "requests": {"requests"},
    "pyyaml": {"yaml"},
    "pillow": {"PIL", "PIL.Image"},
    "django": {"django"},
    "lodash": {"lodash", "_"},
}

CONFIDENCE_MAP = {
    "exact_version": 0.80,
    # TODO(v1.1): add "semver_range" key once range matching is implemented
}


class NewCveDependencyRule(Rule):
    DEFAULT_METADATA = RuleMetadata(
        id="SEC-003",
        name="New CVE Dependency",
        version="1.0.0",
        severity="high",
        confidence=0.8,
        explanation_template=(
            "A newly added dependency {package} {version} has a known vulnerability ({cve_id}). "
            "{description}"
        ),
        enabled=True,
    )

    def __init__(
        self,
        metadata: RuleMetadata | None = None,
        cve_db_path: str | Path | None = None,
    ) -> None:
        self._meta = metadata or self.DEFAULT_METADATA
        db_path = Path(cve_db_path) if cve_db_path else _DEFAULT_CVE_DB
        self._cve_index = self._load_cve_db(db_path)

    @staticmethod
    def _load_cve_db(path: Path) -> dict[tuple[str, str, str], dict]:
        """Build lookup: (package_lower, version, ecosystem_lower) -> {cve_id, description}."""
        index: dict[tuple[str, str, str], dict] = {}
        if not path.exists():
            return index
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in data.get("vulnerabilities", []):
            pkg = entry["package"].lower()
            eco = entry["ecosystem"].lower()
            for version in entry.get("versions", []):
                index[(pkg, version, eco)] = {
                    "cve_id": entry["cve_id"],
                    "description": entry["description"],
                }
        return index

    @property
    def metadata(self) -> RuleMetadata:
        return self._meta

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        all_imports = context.all_imports

        for dep in context.dependency_changes:
            if not dep.is_direct:
                continue
            # Skip unchanged dependencies: old version present and equal to new version
            if dep.old_version is not None and dep.old_version == dep.new_version:
                continue

            key = (dep.package_name.lower(), dep.new_version, dep.ecosystem.lower())
            cve_info = self._cve_index.get(key)
            if not cve_info:
                continue

            if not self._is_imported(dep.package_name, all_imports):
                continue

            evidence = {
                "package": dep.package_name,
                "version": dep.new_version,
                "ecosystem": dep.ecosystem,
                "cve_id": cve_info["cve_id"],
                "description": cve_info["description"],
            }
            findings.append(
                build_finding(
                    meta=self._meta,
                    confidence=CONFIDENCE_MAP["exact_version"],
                    file_path="dependencies",
                    line_number=None,
                    title=f"Vulnerable dependency: {dep.package_name} {dep.new_version} ({cve_info['cve_id']})",
                    evidence=evidence,
                    template_vars={
                        "package": dep.package_name,
                        "version": dep.new_version,
                        "cve_id": cve_info["cve_id"],
                        "description": cve_info["description"],
                    },
                )
            )

        return findings

    @staticmethod
    def _is_imported(package_name: str, all_imports: frozenset[str]) -> bool:
        pkg_lower = package_name.lower()
        import_names = _IMPORT_ALIASES.get(pkg_lower, {pkg_lower})
        return bool(import_names & all_imports)
