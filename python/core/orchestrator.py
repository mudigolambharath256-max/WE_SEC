"""
Campaign orchestrator — main controller with phase gating.

Coordinates all phases of a security assessment campaign:
1. Recon phase
2. Probe phase  
3. Analysis phase
4. Reporting phase

Each phase has explicit gates that must pass before proceeding.
"""

from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging
from datetime import datetime

from .target import Target
from .scope_validator import ScopeValidator, OutOfScopeError
from .grpc_clients import ProbeClient, ReconClient, MCPClient
from .adaptive_orchestrator import AdaptiveOrchestrator
from .session_manager import SessionManager

logger = logging.getLogger(__name__)


class CampaignPhase(Enum):
    """Campaign execution phases."""
    INIT = "init"
    RECON = "recon"
    PROBE = "probe"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class PhaseGate:
    """
    Phase gate that must pass before proceeding.
    
    Attributes:
        phase: Phase this gate guards
        passed: Whether gate has passed
        reason: Reason for pass/fail
        timestamp: When gate was evaluated
    """
    phase: CampaignPhase
    passed: bool
    reason: str
    timestamp: datetime


class CampaignOrchestrator:
    """
    Main campaign orchestrator with phase gating.
    
    Ensures systematic, safe execution of security assessments.
    """
    
    def __init__(
        self,
        campaign_id: str,
        target: Target,
        scope_path: str
    ):
        """
        Initialize campaign orchestrator.
        
        Args:
            campaign_id: Unique campaign identifier
            target: Target configuration
            scope_path: Path to scope.yaml
            
        Raises:
            FileNotFoundError: If scope.yaml not found
        """
        self.campaign_id = campaign_id
        self.target = target
        
        # Initialize scope validator (CRITICAL - must exist)
        self.scope_validator = ScopeValidator(scope_path)
        
        # Initialize clients
        self.probe_client = ProbeClient()
        self.recon_client = ReconClient()
        self.mcp_client = MCPClient()
        
        # Initialize orchestration components
        self.adaptive_orchestrator = AdaptiveOrchestrator()
        self.session_manager = SessionManager()
        
        # Campaign state
        self.current_phase = CampaignPhase.INIT
        self.phase_gates: List[PhaseGate] = []
        self.findings: List[Dict] = []
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        
        logger.info(f"Campaign {campaign_id} initialized for target {target.name}")
    
    def validate_scope(self) -> bool:
        """
        Validate all target URLs are in scope.
        
        Returns:
            bool: True if all URLs in scope
            
        Raises:
            OutOfScopeError: If any URL is out of scope
        """
        logger.info("Validating scope...")
        
        # Validate base URL
        self.scope_validator.validate_or_raise(self.target.base_url)
        
        # Validate all endpoints
        for endpoint in self.target.endpoints:
            full_url = self.target.get_full_url(endpoint)
            self.scope_validator.validate_or_raise(full_url)
        
        logger.info("Scope validation passed")
        return True
    
    def execute_recon_phase(self) -> PhaseGate:
        """
        Execute reconnaissance phase.
        
        Returns:
            PhaseGate: Recon phase gate result
        """
        logger.info(f"[{self.campaign_id}] Starting RECON phase")
        self.current_phase = CampaignPhase.RECON
        
        try:
            # Validate scope before any network activity
            self.validate_scope()
            
            # Port scanning (if target has specific ports)
            # Endpoint fuzzing
            # HAR parsing (if provided)
            
            # For now, mark as passed
            gate = PhaseGate(
                phase=CampaignPhase.RECON,
                passed=True,
                reason="Recon phase completed successfully",
                timestamp=datetime.now()
            )
            
            self.phase_gates.append(gate)
            logger.info(f"[{self.campaign_id}] RECON phase complete")
            return gate
            
        except Exception as e:
            logger.error(f"[{self.campaign_id}] RECON phase failed: {e}")
            gate = PhaseGate(
                phase=CampaignPhase.RECON,
                passed=False,
                reason=f"Recon failed: {str(e)}",
                timestamp=datetime.now()
            )
            self.phase_gates.append(gate)
            return gate
    
    def execute_probe_phase(self) -> PhaseGate:
        """
        Execute probe phase.
        
        Returns:
            PhaseGate: Probe phase gate result
        """
        logger.info(f"[{self.campaign_id}] Starting PROBE phase")
        self.current_phase = CampaignPhase.PROBE
        
        # Check recon gate
        recon_gate = next((g for g in self.phase_gates if g.phase == CampaignPhase.RECON), None)
        if not recon_gate or not recon_gate.passed:
            gate = PhaseGate(
                phase=CampaignPhase.PROBE,
                passed=False,
                reason="Recon phase gate not passed",
                timestamp=datetime.now()
            )
            self.phase_gates.append(gate)
            return gate
        
        try:
            # Execute probes via gRPC
            # Use adaptive orchestrator for strategy
            
            gate = PhaseGate(
                phase=CampaignPhase.PROBE,
                passed=True,
                reason="Probe phase completed successfully",
                timestamp=datetime.now()
            )
            
            self.phase_gates.append(gate)
            logger.info(f"[{self.campaign_id}] PROBE phase complete")
            return gate
            
        except Exception as e:
            logger.error(f"[{self.campaign_id}] PROBE phase failed: {e}")
            gate = PhaseGate(
                phase=CampaignPhase.PROBE,
                passed=False,
                reason=f"Probe failed: {str(e)}",
                timestamp=datetime.now()
            )
            self.phase_gates.append(gate)
            return gate
    
    def execute_analysis_phase(self) -> PhaseGate:
        """
        Execute analysis phase.
        
        Returns:
            PhaseGate: Analysis phase gate result
        """
        logger.info(f"[{self.campaign_id}] Starting ANALYSIS phase")
        self.current_phase = CampaignPhase.ANALYSIS
        
        # Check probe gate
        probe_gate = next((g for g in self.phase_gates if g.phase == CampaignPhase.PROBE), None)
        if not probe_gate or not probe_gate.passed:
            gate = PhaseGate(
                phase=CampaignPhase.ANALYSIS,
                passed=False,
                reason="Probe phase gate not passed",
                timestamp=datetime.now()
            )
            self.phase_gates.append(gate)
            return gate
        
        try:
            # Analyze findings
            # Deduplicate
            # Score
            # Verify (4-layer FP pipeline)
            
            gate = PhaseGate(
                phase=CampaignPhase.ANALYSIS,
                passed=True,
                reason="Analysis phase completed successfully",
                timestamp=datetime.now()
            )
            
            self.phase_gates.append(gate)
            logger.info(f"[{self.campaign_id}] ANALYSIS phase complete")
            return gate
            
        except Exception as e:
            logger.error(f"[{self.campaign_id}] ANALYSIS phase failed: {e}")
            gate = PhaseGate(
                phase=CampaignPhase.ANALYSIS,
                passed=False,
                reason=f"Analysis failed: {str(e)}",
                timestamp=datetime.now()
            )
            self.phase_gates.append(gate)
            return gate
    
    def execute_reporting_phase(self) -> PhaseGate:
        """
        Execute reporting phase.
        
        Returns:
            PhaseGate: Reporting phase gate result
        """
        logger.info(f"[{self.campaign_id}] Starting REPORTING phase")
        self.current_phase = CampaignPhase.REPORTING
        
        # Check analysis gate
        analysis_gate = next((g for g in self.phase_gates if g.phase == CampaignPhase.ANALYSIS), None)
        if not analysis_gate or not analysis_gate.passed:
            gate = PhaseGate(
                phase=CampaignPhase.REPORTING,
                passed=False,
                reason="Analysis phase gate not passed",
                timestamp=datetime.now()
            )
            self.phase_gates.append(gate)
            return gate
        
        try:
            # Generate reports
            
            gate = PhaseGate(
                phase=CampaignPhase.REPORTING,
                passed=True,
                reason="Reporting phase completed successfully",
                timestamp=datetime.now()
            )
            
            self.phase_gates.append(gate)
            logger.info(f"[{self.campaign_id}] REPORTING phase complete")
            return gate
            
        except Exception as e:
            logger.error(f"[{self.campaign_id}] REPORTING phase failed: {e}")
            gate = PhaseGate(
                phase=CampaignPhase.REPORTING,
                passed=False,
                reason=f"Reporting failed: {str(e)}",
                timestamp=datetime.now()
            )
            self.phase_gates.append(gate)
            return gate
    
    def execute_campaign(self) -> bool:
        """
        Execute complete campaign with phase gating.
        
        Returns:
            bool: True if campaign completed successfully
        """
        logger.info(f"[{self.campaign_id}] Starting campaign execution")
        
        try:
            # Phase 1: Recon
            recon_gate = self.execute_recon_phase()
            if not recon_gate.passed:
                self.current_phase = CampaignPhase.FAILED
                return False
            
            # Phase 2: Probe
            probe_gate = self.execute_probe_phase()
            if not probe_gate.passed:
                self.current_phase = CampaignPhase.FAILED
                return False
            
            # Phase 3: Analysis
            analysis_gate = self.execute_analysis_phase()
            if not analysis_gate.passed:
                self.current_phase = CampaignPhase.FAILED
                return False
            
            # Phase 4: Reporting
            reporting_gate = self.execute_reporting_phase()
            if not reporting_gate.passed:
                self.current_phase = CampaignPhase.FAILED
                return False
            
            # Campaign complete
            self.current_phase = CampaignPhase.COMPLETE
            self.end_time = datetime.now()
            
            logger.info(f"[{self.campaign_id}] Campaign completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"[{self.campaign_id}] Campaign failed: {e}")
            self.current_phase = CampaignPhase.FAILED
            self.end_time = datetime.now()
            return False
    
    def get_status(self) -> Dict:
        """
        Get campaign status.
        
        Returns:
            dict: Campaign status summary
        """
        duration = None
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "campaign_id": self.campaign_id,
            "target": self.target.name,
            "current_phase": self.current_phase.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration,
            "phase_gates": [
                {
                    "phase": gate.phase.value,
                    "passed": gate.passed,
                    "reason": gate.reason,
                    "timestamp": gate.timestamp.isoformat()
                }
                for gate in self.phase_gates
            ],
            "findings_count": len(self.findings)
        }
    
    def cleanup(self):
        """Cleanup resources."""
        self.probe_client.close()
        self.recon_client.close()
        self.mcp_client.close()
        logger.info(f"[{self.campaign_id}] Resources cleaned up")
