"""Basic tests that do not require aerleon."""
import os
import unittest
import toml


class TestDocsPackaging(unittest.TestCase):
    """Test Version in doc requirements is the same pyproject."""

    def test_version(self):
        """Verify that pyproject.toml dev dependecies have the same versions as in the docs requirements.txt."""
        parent_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
        poetry_details = toml.load(os.path.join(parent_path, "pyproject.toml"))["tool"]["poetry"]["dev-dependencies"]
        with open(f"{parent_path}/docs/requirements.txt", "r", encoding="utf-8") as file:
            requirements = [line for line in file.read().splitlines() if (len(line) > 0 and not line.startswith("#"))]
        for pkg in requirements:
            if len(pkg.split("==")) == 2:
                pkg, version = pkg.split("==")
            else:
                version = "*"
            self.assertEqual(poetry_details[pkg], version)