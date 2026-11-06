#!/usr/bin/env python3
"""Validate an Apigee API proxy bundle before import or deployment."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Report:
    errors: int = 0
    warnings: int = 0
    messages: list[tuple[str, str]] = field(default_factory=list)

    def add(self, level: str, message: str) -> None:
        self.messages.append((level, message))
        if level == "ERROR":
            self.errors += 1
        elif level == "WARNING":
            self.warnings += 1

    def pass_(self, message: str) -> None:
        self.add("PASS", message)

    def error(self, message: str) -> None:
        self.add("ERROR", message)

    def warning(self, message: str) -> None:
        self.add("WARNING", message)

    def info(self, message: str) -> None:
        self.add("INFO", message)


def local_name(element: ET.Element) -> str:
    """Return an XML tag without an optional namespace."""
    return element.tag.rsplit("}", 1)[-1]


def non_empty_name(element: ET.Element) -> bool:
    return bool(element.get("name", "").strip())


class BundleValidator:
    def __init__(self, bundle: Path) -> None:
        self.bundle = bundle
        self.report = Report()
        self.parsed: dict[Path, ET.Element] = {}

    def relative(self, path: Path) -> str:
        return path.relative_to(self.bundle).as_posix()

    def run(self) -> Report:
        if not self.bundle.is_dir():
            self.report.error(f"apiproxy directory does not exist: {self.bundle}")
            return self.report

        self.report.pass_("apiproxy directory exists")
        self._report_optional_directories()
        self._parse_all_xml()
        self._validate_api_proxy()
        policies = self._discover_policies()
        proxy_steps, target_references = self._validate_endpoints()
        self._validate_policy_references(proxy_steps, policies)
        self._validate_target_references(target_references)
        self._warn_unused_policies(proxy_steps, policies)
        return self.report

    def _report_optional_directories(self) -> None:
        for directory in ("proxies", "policies"):
            path = self.bundle / directory
            if path.is_dir():
                self.report.pass_(f"{directory} directory exists")
            else:
                self.report.info(f"{directory} directory not present")
        for directory in ("targets", "resources"):
            if not (self.bundle / directory).is_dir():
                self.report.info(f"{directory} directory not present")

    def _parse_all_xml(self) -> None:
        for xml_file in sorted(self.bundle.rglob("*.xml")):
            try:
                self.parsed[xml_file] = ET.parse(xml_file).getroot()
                self.report.pass_(self.relative(xml_file))
            except ET.ParseError as exc:
                self.report.error(f"{self.relative(xml_file)}: XML syntax error: {exc}")

    def _validate_api_proxy(self) -> None:
        candidates = [
            (path, root)
            for path, root in self.parsed.items()
            if path.parent == self.bundle and local_name(root) == "APIProxy"
        ]
        if not candidates:
            self.report.error("APIProxy definition not found in bundle root")
            return
        if len(candidates) > 1:
            self.report.error("multiple APIProxy definitions found in bundle root")
            return
        path, root = candidates[0]
        if not non_empty_name(root):
            self.report.error(f"APIProxy definition has missing or empty name: {self.relative(path)}")
            return
        self.report.pass_(f"APIProxy definition valid: {self.relative(path)}")

    def _discover_policies(self) -> dict[str, Path]:
        policies: dict[str, Path] = {}
        policy_dir = self.bundle / "policies"
        if not policy_dir.is_dir():
            return policies
        for path, root in self.parsed.items():
            if path.parent != policy_dir:
                continue
            name = root.get("name", "").strip()
            if not name:
                self.report.error(f"policy has missing or empty name: {self.relative(path)}")
            elif name in policies:
                self.report.error(f"duplicate policy name '{name}': {self.relative(path)}")
            else:
                policies[name] = path
                self.report.pass_(f"policy: {name}")
        return policies

    def _validate_endpoints(self) -> tuple[set[str], list[tuple[str, Path]]]:
        used_policies: set[str] = set()
        target_references: list[tuple[str, Path]] = []
        for directory, expected_root in (("proxies", "ProxyEndpoint"), ("targets", "TargetEndpoint")):
            endpoint_dir = self.bundle / directory
            if not endpoint_dir.is_dir():
                continue
            for path, root in self.parsed.items():
                if path.parent != endpoint_dir:
                    continue
                if local_name(root) != expected_root:
                    self.report.error(
                        f"{self.relative(path)}: expected root element {expected_root}, got {local_name(root)}"
                    )
                    continue
                if not non_empty_name(root):
                    self.report.error(f"{expected_root} has missing or empty name: {self.relative(path)}")
                else:
                    self.report.pass_(f"{expected_root}: {root.get('name')}")
                self._validate_endpoint_configuration(root, path)
                for step in root.iter():
                    if local_name(step) != "Step":
                        continue
                    name_node = next((child for child in step if local_name(child) == "Name"), None)
                    if name_node is not None and (name_node.text or "").strip():
                        used_policies.add((name_node.text or "").strip())
                if expected_root == "ProxyEndpoint":
                    for route_rule in root.iter():
                        if local_name(route_rule) != "RouteRule":
                            continue
                        for child in route_rule:
                            if local_name(child) == "TargetEndpoint" and (child.text or "").strip():
                                target_references.append(((child.text or "").strip(), path))
        return used_policies, target_references

    def _validate_endpoint_configuration(self, root: ET.Element, path: Path) -> None:
        """Validate only endpoint configuration that is actually present."""
        for connection in root.iter():
            if local_name(connection) != "HTTPProxyConnection":
                continue
            self.report.pass_(f"{self.relative(path)}: HTTPProxyConnection")
            for child in connection:
                if local_name(child) == "BasePath":
                    if (child.text or "").strip():
                        self.report.pass_(f"{self.relative(path)}: BasePath")
                    else:
                        self.report.error(f"{self.relative(path)}: BasePath is empty")
        for route_rule in root.iter():
            if local_name(route_rule) == "RouteRule":
                self.report.pass_(f"{self.relative(path)}: RouteRule")

    def _validate_policy_references(self, used: set[str], policies: dict[str, Path]) -> None:
        for name in sorted(used):
            if name in policies:
                self.report.pass_(f"{name} -> policy exists")
            else:
                self.report.error(f"policy referenced by Step does not exist: {name}")

    def _validate_target_references(self, references: list[tuple[str, Path]]) -> None:
        target_names: set[str] = set()
        for path, root in self.parsed.items():
            if path.parent != self.bundle / "targets" or local_name(root) != "TargetEndpoint":
                continue
            name = root.get("name", "").strip()
            if name in target_names:
                self.report.error(f"duplicate TargetEndpoint name: {name}")
            target_names.add(name)
        for name, path in references:
            if name in target_names:
                self.report.pass_(f"{self.relative(path)} -> TargetEndpoint exists: {name}")
            else:
                self.report.error(f"{self.relative(path)}: referenced TargetEndpoint does not exist: {name}")

    def _warn_unused_policies(self, used: set[str], policies: dict[str, Path]) -> None:
        for name in sorted(set(policies) - used):
            self.report.warning(f"policy exists but is not referenced: {name}")


def print_report(report: Report) -> None:
    print("=" * 40)
    print(" APIGEE API PROXY VALIDATOR")
    print("=" * 40)
    for level, message in report.messages:
        print(f"[{level}] {message}")
    print("-" * 40)
    print(f"Errors:   {report.errors}")
    print(f"Warnings: {report.warnings}")
    print(f"VALIDATION RESULT: {'PASS' if report.errors == 0 else 'FAIL'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="path to the apiproxy directory")
    args = parser.parse_args(argv)
    report = BundleValidator(args.bundle).run()
    print_report(report)
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
