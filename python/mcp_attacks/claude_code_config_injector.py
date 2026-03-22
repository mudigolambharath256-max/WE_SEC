"""Claude Code configuration injection."""
import logging
from typing import List, Dict, Any
from ..core.scope_validator import ScopeValidator
logger = logging.getLogger(__name__)
class ClaudeCodeConfigInjector:
    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
    def run(self, target_url: str, campaign_id: str) -> List[Dict[str, Any]]:
        self.scope_validator.validate_or_raise(target_url)
        return []
logger.info("Claude Code config injector module loaded")
