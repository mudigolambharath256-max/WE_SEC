"""
CVSS 4.0 scoring engine for security findings.

Implements CVSS 4.0 base score calculation according to FIRST specification.
Provides automated scoring based on finding characteristics and manual
override capabilities for operator review.

CVSS 4.0 metrics:
- Attack Vector (AV): Network, Adjacent, Local, Physical
- Attack Complexity (AC): Low, High
- Attack Requirements (AT): None, Present
- Privileges Required (PR): None, Low, High
- User Interaction (UI): None, Passive, Active
- Confidentiality (VC/SC): None, Low, High
- Integrity (VI/SI): None, Low, High
- Availability (VA/SA): None, Low, High

Reference: https://www.first.org/cvss/v4.0/specification-document
"""

import logging
from typing import Dict, Tuple, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class AttackVector(Enum):
    """CVSS 4.0 Attack Vector (AV)"""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    """CVSS 4.0 Attack Complexity (AC)"""
    LOW = "L"
    HIGH = "H"


class AttackRequirements(Enum):
    """CVSS 4.0 Attack Requirements (AT)"""
    NONE = "N"
    PRESENT = "P"


class PrivilegesRequired(Enum):
    """CVSS 4.0 Privileges Required (PR)"""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    """CVSS 4.0 User Interaction (UI)"""
    NONE = "N"
    PASSIVE = "P"
    ACTIVE = "A"


class Impact(Enum):
    """CVSS 4.0 Impact (C/I/A)"""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


# CVSS 4.0 base score lookup table (simplified)
# Full implementation would use the complete FIRST lookup table
# This is a representative subset for common vulnerability patterns
CVSS_LOOKUP = {
    # Format: (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA) -> score
    # Network-based, low complexity, no auth, high impact
    ("N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H"): 10.0,
    ("N", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"): 9.3,
    ("N", "L", "N", "N", "N", "H", "N", "N", "H", "N", "N"): 8.7,
    ("N", "L", "N", "N", "N", "L", "L", "L", "L", "L", "L"): 6.9,
    ("N", "L", "N", "N", "P", "H", "H", "N", "H", "H", "N"): 8.3,
    ("N", "L", "N", "N", "P", "L", "L", "N", "L", "L", "N"): 5.4,
    ("N", "L", "N", "L", "N", "H", "H", "N", "H", "H", "N"): 8.8,
    ("N", "L", "N", "L", "N", "L", "L", "N", "L", "L", "N"): 6.5,
    ("N", "L", "N", "L", "P", "H", "H", "N", "H", "H", "N"): 7.1,
    ("N", "L", "N", "L", "P", "L", "L", "N", "L", "L", "N"): 4.3,
    ("N", "H", "N", "N", "N", "H", "H", "N", "H", "H", "N"): 8.1,
    ("N", "H", "N", "N", "N", "L", "L", "N", "L", "L", "N"): 5.9,
    ("N", "H", "N", "N", "P", "H", "H", "N", "H", "H", "N"): 6.8,
    ("N", "H", "N", "N", "P", "L", "L", "N", "L", "L", "N"): 3.9,
    # Adjacent network
    ("A", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"): 8.0,
    ("A", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"): 5.7,
    # Local
    ("L", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"): 7.3,
    ("L", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"): 4.8,
    # Info disclosure only
    ("N", "L", "N", "N", "N", "H", "N", "N", "H", "N", "N"): 7.5,
    ("N", "L", "N", "N", "N", "L", "N", "N", "L", "N", "N"): 5.3,
}


class CVSSScorer:
    """
    CVSS 4.0 scoring engine.

    Automatically calculates CVSS scores based on finding characteristics.
    Provides both automated scoring and manual override capabilities.

    Usage:
        scorer = CVSSScorer()
        score, vector = scorer.score_finding(
            finding_family="prompt_injection",
            finding_type="jailbreak",
            oob_callback=False,
            requires_auth=False,
        )
    """

    def __init__(self):
        """Initializes CVSS scorer with default mappings."""
        # Map finding families to default CVSS metrics
        self.family_defaults = {
            "prompt_injection": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.NONE,
                "PR": PrivilegesRequired.NONE,
                "UI": UserInteraction.PASSIVE,
                "VC": Impact.HIGH,
                "VI": Impact.HIGH,
                "VA": Impact.NONE,
                "SC": Impact.HIGH,
                "SI": Impact.HIGH,
                "SA": Impact.NONE,
            },
            "rce": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.NONE,
                "PR": PrivilegesRequired.NONE,
                "UI": UserInteraction.NONE,
                "VC": Impact.HIGH,
                "VI": Impact.HIGH,
                "VA": Impact.HIGH,
                "SC": Impact.HIGH,
                "SI": Impact.HIGH,
                "SA": Impact.HIGH,
            },
            "ssrf": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.NONE,
                "PR": PrivilegesRequired.NONE,
                "UI": UserInteraction.NONE,
                "VC": Impact.HIGH,
                "VI": Impact.LOW,
                "VA": Impact.NONE,
                "SC": Impact.HIGH,
                "SI": Impact.LOW,
                "SA": Impact.NONE,
            },
            "data_exfiltration": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.NONE,
                "PR": PrivilegesRequired.NONE,
                "UI": UserInteraction.PASSIVE,
                "VC": Impact.HIGH,
                "VI": Impact.NONE,
                "VA": Impact.NONE,
                "SC": Impact.HIGH,
                "SI": Impact.NONE,
                "SA": Impact.NONE,
            },
            "idor": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.NONE,
                "PR": PrivilegesRequired.LOW,
                "UI": UserInteraction.NONE,
                "VC": Impact.HIGH,
                "VI": Impact.LOW,
                "VA": Impact.NONE,
                "SC": Impact.HIGH,
                "SI": Impact.LOW,
                "SA": Impact.NONE,
            },
            "mcp_tool_poisoning": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.NONE,
                "PR": PrivilegesRequired.NONE,
                "UI": UserInteraction.PASSIVE,
                "VC": Impact.HIGH,
                "VI": Impact.HIGH,
                "VA": Impact.LOW,
                "SC": Impact.HIGH,
                "SI": Impact.HIGH,
                "SA": Impact.LOW,
            },
            "mcp_rug_pull": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.PRESENT,
                "PR": PrivilegesRequired.NONE,
                "UI": UserInteraction.PASSIVE,
                "VC": Impact.HIGH,
                "VI": Impact.HIGH,
                "VA": Impact.NONE,
                "SC": Impact.HIGH,
                "SI": Impact.HIGH,
                "SA": Impact.NONE,
            },
            "info_disclosure": {
                "AV": AttackVector.NETWORK,
                "AC": AttackComplexity.LOW,
                "AT": AttackRequirements.NONE,
                "PR": PrivilegesRequired.NONE,
                "UI": UserInteraction.NONE,
                "VC": Impact.LOW,
                "VI": Impact.NONE,
                "VA": Impact.NONE,
                "SC": Impact.LOW,
                "SI": Impact.NONE,
                "SA": Impact.NONE,
            },
        }

    def score_finding(
        self,
        finding_family: str,
        finding_type: str,
        oob_callback: bool = False,
        requires_auth: bool = False,
        requires_user_interaction: bool = False,
        high_complexity: bool = False,
    ) -> Tuple[float, str]:
        """
        Calculates CVSS 4.0 score for a finding.

        Args:
            finding_family: Normalized finding family (from FAMILY_MAP)
            finding_type: Specific finding type
            oob_callback: True if confirmed via OOB callback
            requires_auth: True if attack requires authentication
            requires_user_interaction: True if attack requires user action
            high_complexity: True if attack is complex to execute

        Returns:
            Tuple[float, str]: (cvss_score, cvss_vector)
                cvss_score: Base score 0.0-10.0
                cvss_vector: CVSS 4.0 vector string

        Example:
            score, vector = scorer.score_finding(
                finding_family="prompt_injection",
                finding_type="jailbreak",
                oob_callback=False,
                requires_auth=False,
            )
            # Returns: (9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")
        """
        # Get default metrics for finding family
        if finding_family not in self.family_defaults:
            logger.warning(f"Unknown finding family: {finding_family}, using info_disclosure defaults")
            metrics = self.family_defaults["info_disclosure"].copy()
        else:
            metrics = self.family_defaults[finding_family].copy()

        # Apply modifiers based on finding characteristics
        if requires_auth:
            metrics["PR"] = PrivilegesRequired.LOW
        
        if requires_user_interaction:
            metrics["UI"] = UserInteraction.ACTIVE
        
        if high_complexity:
            metrics["AC"] = AttackComplexity.HIGH

        # OOB callback confirms exploitability — increases confidence
        if oob_callback:
            # OOB confirmation means we have definitive proof
            # Increase impact if it was LOW
            if metrics["VC"] == Impact.LOW:
                metrics["VC"] = Impact.HIGH
            if metrics["SC"] == Impact.LOW:
                metrics["SC"] = Impact.HIGH

        # Build CVSS vector string
        vector = self._build_vector(metrics)

        # Calculate score from lookup table
        score = self._calculate_score(metrics)

        logger.debug(f"Scored {finding_family}/{finding_type}: {score} {vector}")
        return score, vector

    def _build_vector(self, metrics: Dict[str, Enum]) -> str:
        """
        Builds CVSS 4.0 vector string from metrics.

        Args:
            metrics: Dictionary of CVSS metrics

        Returns:
            str: CVSS 4.0 vector string

        Example:
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
        """
        vector_parts = ["CVSS:4.0"]
        vector_parts.append(f"AV:{metrics['AV'].value}")
        vector_parts.append(f"AC:{metrics['AC'].value}")
        vector_parts.append(f"AT:{metrics['AT'].value}")
        vector_parts.append(f"PR:{metrics['PR'].value}")
        vector_parts.append(f"UI:{metrics['UI'].value}")
        vector_parts.append(f"VC:{metrics['VC'].value}")
        vector_parts.append(f"VI:{metrics['VI'].value}")
        vector_parts.append(f"VA:{metrics['VA'].value}")
        vector_parts.append(f"SC:{metrics['SC'].value}")
        vector_parts.append(f"SI:{metrics['SI'].value}")
        vector_parts.append(f"SA:{metrics['SA'].value}")
        return "/".join(vector_parts)

    def _calculate_score(self, metrics: Dict[str, Enum]) -> float:
        """
        Calculates CVSS 4.0 base score from metrics.

        Uses lookup table for common patterns. Falls back to heuristic
        calculation if exact match not found.

        Args:
            metrics: Dictionary of CVSS metrics

        Returns:
            float: CVSS base score 0.0-10.0
        """
        # Build lookup key
        key = (
            metrics["AV"].value,
            metrics["AC"].value,
            metrics["AT"].value,
            metrics["PR"].value,
            metrics["UI"].value,
            metrics["VC"].value,
            metrics["VI"].value,
            metrics["VA"].value,
            metrics["SC"].value,
            metrics["SI"].value,
            metrics["SA"].value,
        )

        # Try exact lookup
        if key in CVSS_LOOKUP:
            return CVSS_LOOKUP[key]

        # Fallback: heuristic calculation
        # This is a simplified approximation — full CVSS 4.0 uses complex formulas
        score = 0.0

        # Base exploitability (0-4 points)
        if metrics["AV"] == AttackVector.NETWORK:
            score += 1.5
        elif metrics["AV"] == AttackVector.ADJACENT:
            score += 1.0
        elif metrics["AV"] == AttackVector.LOCAL:
            score += 0.5

        if metrics["AC"] == AttackComplexity.LOW:
            score += 1.0
        else:
            score += 0.5

        if metrics["PR"] == PrivilegesRequired.NONE:
            score += 1.0
        elif metrics["PR"] == PrivilegesRequired.LOW:
            score += 0.5

        if metrics["UI"] == UserInteraction.NONE:
            score += 0.5

        # Impact (0-6 points)
        impact_score = 0.0
        for impact_metric in ["VC", "VI", "VA", "SC", "SI", "SA"]:
            if metrics[impact_metric] == Impact.HIGH:
                impact_score += 1.0
            elif metrics[impact_metric] == Impact.LOW:
                impact_score += 0.5

        score += impact_score

        # Normalize to 0-10 range
        score = min(10.0, score)
        score = round(score, 1)

        logger.debug(f"Heuristic CVSS score calculated: {score}")
        return score

    def parse_vector(self, vector: str) -> Dict[str, str]:
        """
        Parses CVSS 4.0 vector string into metrics dictionary.

        Args:
            vector: CVSS 4.0 vector string

        Returns:
            dict: Metrics dictionary

        Raises:
            ValueError: If vector is malformed

        Example:
            metrics = scorer.parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")
            # Returns: {"AV": "N", "AC": "L", ...}
        """
        if not vector.startswith("CVSS:4.0/"):
            raise ValueError(f"Invalid CVSS 4.0 vector: {vector}")

        parts = vector.split("/")[1:]  # Skip "CVSS:4.0"
        metrics = {}
        for part in parts:
            if ":" not in part:
                raise ValueError(f"Malformed vector component: {part}")
            key, value = part.split(":")
            metrics[key] = value

        return metrics

    def severity_from_score(self, score: float) -> str:
        """
        Maps CVSS score to severity level.

        Args:
            score: CVSS base score 0.0-10.0

        Returns:
            str: critical | high | medium | low | info

        CVSS 4.0 severity ratings:
        - 9.0-10.0: Critical
        - 7.0-8.9: High
        - 4.0-6.9: Medium
        - 0.1-3.9: Low
        - 0.0: Info
        """
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0.0:
            return "low"
        else:
            return "info"


logger.info("CVSS scorer module loaded")
