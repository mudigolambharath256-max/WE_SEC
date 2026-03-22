"""
Promptfoo LLM evaluation runner.

Integrates Promptfoo for LLM evaluation and red teaming.
"""

import logging
from typing import List, Dict, Any

from ..core.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)


class PromptfooRunner:
    """Promptfoo LLM evaluation runner."""

    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
        logger.info("Promptfoo runner initialized")

    def run(self, target_url: str, campaign_id: str) -> List[Dict[str, Any]]:
        """Runs Promptfoo evaluation."""
        self.scope_validator.validate_or_raise(target_url)
        logger.info(f"Running Promptfoo evaluation: {target_url}")
        return []


logger.info("Promptfoo runner module loaded")
