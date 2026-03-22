"""
Adaptive orchestrator — dynamically adjusts attack strategy based on feedback.

Coordinates progressive probing, context profiling, and attack selection
to optimize campaign effectiveness.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import logging

from .progressive_prober import ProgressiveProber, ProbeLevel, categorize_payloads_by_level
from .context_profiler import ContextProfiler
from .response_classifier import classify, ClassificationState
from .chat_template_injector import ChatTemplateInjector

logger = logging.getLogger(__name__)


@dataclass
class AdaptiveStrategy:
    """
    Adaptive attack strategy configuration.
    
    Attributes:
        probe_level: Current probe difficulty level
        template_id: Chat template to use
        attack_types: Prioritized list of attack types
        rate_limit_ms: Current rate limit
        concurrency: Current concurrency level
    """
    probe_level: ProbeLevel
    template_id: Optional[str]
    attack_types: List[str]
    rate_limit_ms: int
    concurrency: int


class AdaptiveOrchestrator:
    """
    Orchestrates adaptive attack strategy based on real-time feedback.
    """
    
    def __init__(
        self,
        initial_rate_limit_ms: int = 200,
        initial_concurrency: int = 5
    ):
        """
        Initialize adaptive orchestrator.
        
        Args:
            initial_rate_limit_ms: Initial rate limit in milliseconds
            initial_concurrency: Initial concurrency level
        """
        self.progressive_prober = ProgressiveProber()
        self.context_profiler = ContextProfiler()
        self.template_injector: Optional[ChatTemplateInjector] = None
        
        self.current_strategy = AdaptiveStrategy(
            probe_level=ProbeLevel.BENIGN,
            template_id=None,
            attack_types=["chatinject", "flipattack"],
            rate_limit_ms=initial_rate_limit_ms,
            concurrency=initial_concurrency
        )
        
        self.probe_count = 0
        self.success_count = 0
        
        logger.info("AdaptiveOrchestrator initialized")
    
    def process_probe_result(
        self,
        payload: str,
        response: str,
        level: ProbeLevel
    ) -> ClassificationState:
        """
        Process a probe result and update strategy.
        
        Args:
            payload: Payload sent
            response: Response received
            level: Probe level used
            
        Returns:
            ClassificationState: Response classification
        """
        # Classify response
        classification = classify(response)
        
        # Record in progressive prober
        self.progressive_prober.record_probe_result(
            level, payload, response, classification
        )
        
        # Update counters
        self.probe_count += 1
        if classification in [ClassificationState.FULL, ClassificationState.PARTIAL]:
            self.success_count += 1
        
        # Update strategy based on results
        self._update_strategy()
        
        logger.debug(f"Probe processed: classification={classification.value}, "
                    f"success_rate={self.success_count/self.probe_count:.2f}")
        
        return classification
    
    def _update_strategy(self):
        """Update attack strategy based on accumulated results."""
        # Update probe level
        new_level = self.progressive_prober.get_next_level()
        if new_level != self.current_strategy.probe_level:
            logger.info(f"Strategy updated: probe_level {self.current_strategy.probe_level.name} -> {new_level.name}")
            self.current_strategy.probe_level = new_level
        
        # Adjust rate limiting based on success rate
        if self.probe_count >= 10:
            success_rate = self.success_count / self.probe_count
            
            # Increase rate if high success (target is vulnerable)
            if success_rate > 0.5 and self.current_strategy.rate_limit_ms > 100:
                self.current_strategy.rate_limit_ms = max(100, self.current_strategy.rate_limit_ms - 50)
                logger.info(f"Rate limit decreased to {self.current_strategy.rate_limit_ms}ms (high success)")
            
            # Decrease rate if low success (avoid detection)
            elif success_rate < 0.1 and self.current_strategy.rate_limit_ms < 500:
                self.current_strategy.rate_limit_ms = min(500, self.current_strategy.rate_limit_ms + 50)
                logger.info(f"Rate limit increased to {self.current_strategy.rate_limit_ms}ms (low success)")
        
        # Update attack types based on level
        self.current_strategy.attack_types = self._get_attack_types_for_level(
            self.current_strategy.probe_level
        )
    
    def _get_attack_types_for_level(self, level: ProbeLevel) -> List[str]:
        """
        Get recommended attack types for probe level.
        
        Args:
            level: Probe level
            
        Returns:
            list: Attack type names
        """
        attack_map = {
            ProbeLevel.BENIGN: ["chatinject"],
            ProbeLevel.MILD: ["chatinject", "flipattack"],
            ProbeLevel.MODERATE: ["chatinject", "flipattack", "unicode_injection"],
            ProbeLevel.AGGRESSIVE: ["chatinject", "flipattack", "unicode_injection", "adversarial_poetry"],
            ProbeLevel.EXTREME: ["chatinject", "flipattack", "unicode_injection", "adversarial_poetry", "multilingual"],
        }
        
        return attack_map.get(level, ["chatinject"])
    
    def profile_target(self, probe_responses: List[Dict[str, str]]):
        """
        Profile target from initial probe responses.
        
        Args:
            probe_responses: List of {prompt, response} dicts
        """
        profile = self.context_profiler.profile_target(probe_responses)
        
        # Update strategy based on profile
        if profile.template_format:
            self.current_strategy.template_id = profile.template_format
            self.template_injector = ChatTemplateInjector(profile.template_format)
            logger.info(f"Template detected: {profile.template_format}")
        
        # Get recommended attacks from profiler
        recommended = self.context_profiler.get_recommended_attacks()
        if recommended:
            self.current_strategy.attack_types = recommended
            logger.info(f"Attack types updated from profile: {recommended}")
    
    def select_next_payloads(
        self,
        available_payloads: Dict[ProbeLevel, List[str]],
        count: int = 10
    ) -> List[str]:
        """
        Select next batch of payloads based on current strategy.
        
        Args:
            available_payloads: Map of level to payload lists
            count: Number of payloads to select
            
        Returns:
            list: Selected payloads
        """
        return self.progressive_prober.select_payloads_for_level(
            self.current_strategy.probe_level,
            available_payloads,
            count
        )
    
    def get_current_strategy(self) -> AdaptiveStrategy:
        """
        Get current attack strategy.
        
        Returns:
            AdaptiveStrategy: Current strategy
        """
        return self.current_strategy
    
    def should_continue(self, max_probes: int = 1000) -> bool:
        """
        Determine if campaign should continue.
        
        Args:
            max_probes: Maximum number of probes
            
        Returns:
            bool: True if should continue
        """
        # Stop if max probes reached
        if self.probe_count >= max_probes:
            logger.info(f"Max probes reached: {max_probes}")
            return False
        
        # Stop if at max level with low success
        if self.current_strategy.probe_level == ProbeLevel.EXTREME:
            if self.probe_count >= 100:
                success_rate = self.success_count / self.probe_count
                if success_rate < 0.05:
                    logger.info(f"Stopping: at max level with low success rate {success_rate:.2f}")
                    return False
        
        return True
    
    def get_statistics(self) -> Dict:
        """
        Get orchestrator statistics.
        
        Returns:
            dict: Statistics summary
        """
        prober_stats = self.progressive_prober.get_statistics()
        
        return {
            "total_probes": self.probe_count,
            "total_successes": self.success_count,
            "overall_success_rate": self.success_count / self.probe_count if self.probe_count > 0 else 0.0,
            "current_strategy": {
                "probe_level": self.current_strategy.probe_level.name,
                "template_id": self.current_strategy.template_id,
                "attack_types": self.current_strategy.attack_types,
                "rate_limit_ms": self.current_strategy.rate_limit_ms,
                "concurrency": self.current_strategy.concurrency,
            },
            "prober_stats": prober_stats
        }
    
    def reset(self):
        """Reset orchestrator state."""
        self.progressive_prober.reset()
        self.current_strategy = AdaptiveStrategy(
            probe_level=ProbeLevel.BENIGN,
            template_id=None,
            attack_types=["chatinject", "flipattack"],
            rate_limit_ms=200,
            concurrency=5
        )
        self.probe_count = 0
        self.success_count = 0
        logger.info("AdaptiveOrchestrator reset")
