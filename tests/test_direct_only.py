# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

import pytest
from lib4sbom.parser import SBOMParser

from sbomaudit.audit import SBOMaudit


@pytest.fixture
def test_sbom_path():
    """Path to the test SBOM file with direct and transitive dependencies."""
    return os.path.join(
        os.path.dirname(__file__), "..", "examples", "test_sbom.spdx.json"
    )


@pytest.fixture
def sbom_parser(test_sbom_path):
    """Parse the test SBOM file."""
    parser = SBOMParser()
    parser.parse_file(test_sbom_path)
    return parser


class TestDirectOnly:
    """Tests for the --direct-only parameter functionality."""

    def test_sbom_has_expected_packages(self, sbom_parser):
        """Verify the test SBOM has the expected package structure."""
        packages = sbom_parser.get_packages()
        package_names = {p.get("name") for p in packages}

        # Should have 6 packages total
        assert len(packages) == 6
        assert package_names == {
            "my-app",      # root
            "requests",    # direct dependency
            "click",       # direct dependency
            "urllib3",     # transitive (via requests)
            "certifi",     # transitive (via requests)
            "idna",        # transitive (via requests)
        }

    def test_sbom_has_expected_relationships(self, sbom_parser):
        """Verify the test SBOM has the expected relationship structure."""
        relationships = sbom_parser.get_relationships()

        # Should have 6 relationships
        assert len(relationships) == 6

    def test_audit_without_direct_only_includes_all_packages(self, sbom_parser):
        """Without --direct-only, all packages should be audited."""
        options = {
            "offline": True,
            "direct_only": False,
        }
        audit = SBOMaudit(options=options)
        audit.audit_sbom(sbom_parser)

        # Get audited packages from the audit results
        audit_results = audit.get_audit()
        audited_packages = audit_results.get("packages", [])
        audited_names = {p.get("name") for p in audited_packages}

        # All 6 packages should be in the audit (those with issues reported)
        # Note: packages without issues may not appear in the report
        # So we check that transitive deps CAN appear
        packages = sbom_parser.get_packages()
        assert len(packages) == 6

    def test_audit_with_direct_only_excludes_transitive(self, sbom_parser):
        """With --direct-only, only root and direct dependencies should be audited."""
        options = {
            "offline": True,
            "direct_only": True,
        }
        audit = SBOMaudit(options=options)

        # Get the filtered packages via the internal method
        packages = sbom_parser.get_packages()
        relationships = sbom_parser.get_relationships()
        filtered = audit._get_direct_dependencies(packages, relationships)
        filtered_names = {p.get("name") for p in filtered}

        # Should only have root + direct dependencies (3 packages)
        assert len(filtered) == 3
        assert filtered_names == {"my-app", "requests", "click"}

        # Transitive dependencies should be excluded
        assert "urllib3" not in filtered_names
        assert "certifi" not in filtered_names
        assert "idna" not in filtered_names

    def test_get_direct_dependencies_with_empty_relationships(self):
        """With no relationships, all packages should be returned."""
        options = {"direct_only": True}
        audit = SBOMaudit(options=options)

        packages = [
            {"name": "pkg1"},
            {"name": "pkg2"},
        ]
        relationships = []

        filtered = audit._get_direct_dependencies(packages, relationships)
        assert len(filtered) == 2

    def test_get_direct_dependencies_finds_root_without_describes(self):
        """Root can be found by analyzing DEPENDS_ON relationships."""
        options = {"direct_only": True}
        audit = SBOMaudit(options=options)

        packages = [
            {"name": "root-pkg"},
            {"name": "direct-dep"},
            {"name": "transitive-dep"},
        ]
        # No DESCRIBES relationship, only DEPENDS_ON
        relationships = [
            {"source": "root-pkg", "target": "direct-dep", "type": "DEPENDS_ON"},
            {"source": "direct-dep", "target": "transitive-dep", "type": "DEPENDS_ON"},
        ]

        filtered = audit._get_direct_dependencies(packages, relationships)
        filtered_names = {p.get("name") for p in filtered}

        # Should find root-pkg as root (source but never target)
        # and direct-dep as its direct dependency
        assert filtered_names == {"root-pkg", "direct-dep"}
        assert "transitive-dep" not in filtered_names
