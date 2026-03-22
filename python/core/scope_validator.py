"""
Scope validator — guards every probe against out-of-scope URLs.

This module is the first line of defence against accidental out-of-scope
testing. It must be called at the entry point of every attack function
before any network request is made.

Every violation raises OutOfScopeError immediately. Silent skips are
never permitted — the operator must be informed when a probe is blocked.
"""

import yaml
from urllib.parse import urlparse
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class OutOfScopeError(Exception):
    """Raised when a URL or action is outside the defined scope."""
    pass


class ScopeValidator:
    """
    Validates URLs and actions against the scope.yaml configuration.

    Args:
        scope_path: Path to scope.yaml file

    Raises:
        FileNotFoundError: If scope.yaml does not exist
        yaml.YAMLError: If scope.yaml is malformed
    """

    def __init__(self, scope_path: str):
        scope_file = Path(scope_path)
        if not scope_file.exists():
            raise FileNotFoundError(
                f"scope.yaml not found at {scope_path}. "
                f"Every campaign requires a scope file. "
                f"Copy config/scope.yaml and fill in your target."
            )
        self.scope = yaml.safe_load(scope_file.read_text())
        self.allowed_domains = self.scope.get(
            "scope_boundaries", {}).get("allowed_domains", [])
        self.excluded_paths = self.scope.get(
            "scope_boundaries", {}).get("excluded_paths", [])
        self.excluded_extensions = self.scope.get(
            "scope_boundaries", {}).get("excluded_extensions", [])
        logger.info(
            f"Scope loaded: {len(self.allowed_domains)} allowed domains, "
            f"{len(self.excluded_paths)} excluded paths"
        )

    def is_in_scope(self, url: str) -> bool:
        """Returns True if url is within the defined scope."""
        parsed = urlparse(url)
        if parsed.hostname not in self.allowed_domains:
            return False
        for excluded in self.excluded_paths:
            if parsed.path.startswith(excluded):
                return False
        for ext in self.excluded_extensions:
            if parsed.path.endswith(ext):
                return False
        return True

    def validate_or_raise(self, url: str):
        """
        Validates url against scope. Raises OutOfScopeError if not in scope.

        Call this at the entry point of every attack function.

        Args:
            url: The URL to validate

        Raises:
            OutOfScopeError: If url is not in scope
        """
        if not self.is_in_scope(url):
            msg = (
                f"OUT OF SCOPE: {url}\n"
                f"Allowed domains: {self.allowed_domains}\n"
                f"Excluded paths: {self.excluded_paths}\n"
                f"Review scope.yaml before proceeding."
            )
            logger.error(msg)
            raise OutOfScopeError(msg)
