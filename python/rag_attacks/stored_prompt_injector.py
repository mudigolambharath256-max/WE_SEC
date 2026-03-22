"""
Stored prompt injection via documents.

Tests persistent prompt injection by embedding attacks in documents
that are stored in RAG knowledge bases.
"""

import logging
from typing import List, Dict, Any

from ..core.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)


class StoredPromptInjector:
    """Stored prompt injection via documents."""

    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
        logger.info("Stored prompt injector initialized")

    def inject_stored_prompts(self, upload_url: str, campaign_id: str) -> List[Dict[str, Any]]:
        """Injects stored prompt injection payloads."""
        self.scope_validator.validate_or_raise(upload_url)
        logger.info(f"Injecting stored prompts: {upload_url}")
        return []


logger.info("Stored prompt injector module loaded")
