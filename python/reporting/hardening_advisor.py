"""
Hardening advisor for llmrt.

Provides remediation guidance and hardening recommendations based on
campaign findings. Generates actionable security improvements.

Usage:
    advisor = HardeningAdvisor()
    recommendations = advisor.generate_recommendations(findings_list)
    hardening_plan = advisor.create_hardening_plan(findings_list)
"""

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class HardeningAdvisor:
    """
    Generates security hardening recommendations.

    Provides actionable remediation guidance based on campaign findings.
    """

    def __init__(self):
        """Initializes hardening advisor."""
        self.remediation_db = self._build_remediation_db()
        logger.info("Hardening advisor initialized")

    def _build_remediation_db(self) -> Dict:
        """Builds remediation guidance database."""
        return {
            "prompt_injection": {
                "immediate": [
                    "Implement input validation and sanitization",
                    "Add prompt filtering layer",
                    "Enable output validation"
                ],
                "short_term": [
                    "Implement instruction hierarchy",
                    "Add privilege control on backend access",
                    "Deploy adversarial training"
                ],
                "long_term": [
                    "Implement zero-trust architecture",
                    "Deploy continuous monitoring",
                    "Regular security assessments"
                ]
            },
            "rce": {
                "immediate": [
                    "Disable code execution features",
                    "Implement sandboxing",
                    "Add output validation"
                ],
                "short_term": [
                    "Deploy code execution monitoring",
                    "Implement least privilege",
                    "Add security logging"
                ],
                "long_term": [
                    "Redesign architecture to eliminate code execution",
                    "Implement formal verification",
                    "Regular penetration testing"
                ]
            },
            "sql_injection": {
                "immediate": [
                    "Use parameterized queries",
                    "Implement input validation",
                    "Apply least privilege to database access"
                ],
                "short_term": [
                    "Deploy WAF with SQL injection rules",
                    "Implement query monitoring",
                    "Add database activity monitoring"
                ],
                "long_term": [
                    "Migrate to ORM framework",
                    "Implement query allowlisting",
                    "Regular database security audits"
                ]
            },
            "pii_leak": {
                "immediate": [
                    "Implement output filtering",
                    "Add data classification",
                    "Enable PII detection"
                ],
                "short_term": [
                    "Deploy DLP solutions",
                    "Implement differential privacy",
                    "Add access controls"
                ],
                "long_term": [
                    "Implement privacy-by-design",
                    "Deploy data minimization",
                    "Regular privacy audits"
                ]
            },
            "mcp_tool_injection": {
                "immediate": [
                    "Validate all tool inputs",
                    "Implement tool sandboxing",
                    "Add input sanitization"
                ],
                "short_term": [
                    "Deploy tool usage monitoring",
                    "Implement permission boundaries",
                    "Add security logging"
                ],
                "long_term": [
                    "Implement tool verification framework",
                    "Deploy continuous tool auditing",
                    "Regular security assessments"
                ]
            },
            "mcp_rug_pull": {
                "immediate": [
                    "Implement tool verification",
                    "Add update monitoring",
                    "Enable rollback capability"
                ],
                "short_term": [
                    "Deploy tool signing",
                    "Implement version pinning",
                    "Add change detection"
                ],
                "long_term": [
                    "Implement supply chain security framework",
                    "Deploy continuous monitoring",
                    "Regular tool audits"
                ]
            },
            "oauth_confused_deputy": {
                "immediate": [
                    "Implement PKCE",
                    "Add state parameter validation",
                    "Enable token binding"
                ],
                "short_term": [
                    "Deploy OAuth security best practices",
                    "Implement token validation",
                    "Add security logging"
                ],
                "long_term": [
                    "Migrate to OAuth 2.1",
                    "Implement zero-trust OAuth",
                    "Regular OAuth audits"
                ]
            },
            "rag_poisoning": {
                "immediate": [
                    "Validate knowledge base sources",
                    "Implement content sanitization",
                    "Add source verification"
                ],
                "short_term": [
                    "Deploy anomaly detection",
                    "Implement content monitoring",
                    "Add integrity checks"
                ],
                "long_term": [
                    "Implement trusted source framework",
                    "Deploy continuous monitoring",
                    "Regular content audits"
                ]
            },
        }

    def generate_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """
        Generates remediation recommendations for findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            list: List of recommendations with priorities
        """
        recommendations = []
        
        # Group findings by family
        family_groups = {}
        for finding in findings:
            family = finding.get("family", "unknown")
            if family not in family_groups:
                family_groups[family] = []
            family_groups[family].append(finding)
        
        # Generate recommendations per family
        for family, family_findings in family_groups.items():
            remediation = self.remediation_db.get(family)
            
            if not remediation:
                logger.warning(f"No remediation guidance for: {family}")
                continue
            
            # Calculate priority based on severity and count
            max_severity = max(
                (f.get("severity", "info") for f in family_findings),
                key=lambda s: ["critical", "high", "medium", "low", "info"].index(s)
                if s in ["critical", "high", "medium", "low", "info"] else 4
            )
            
            count = len(family_findings)
            priority = self._calculate_priority(max_severity, count)
            
            recommendation = {
                "family": family,
                "finding_count": count,
                "max_severity": max_severity,
                "priority": priority,
                "immediate_actions": remediation["immediate"],
                "short_term_actions": remediation["short_term"],
                "long_term_actions": remediation["long_term"],
                "affected_findings": [f.get("id") for f in family_findings]
            }
            
            recommendations.append(recommendation)
        
        # Sort by priority
        recommendations.sort(key=lambda r: r["priority"], reverse=True)
        
        logger.info(f"Generated {len(recommendations)} recommendations")
        return recommendations

    def _calculate_priority(self, severity: str, count: int) -> int:
        """Calculates priority score (0-100)."""
        severity_scores = {
            "critical": 40,
            "high": 30,
            "medium": 20,
            "low": 10,
            "info": 5
        }
        
        base_score = severity_scores.get(severity, 5)
        count_multiplier = min(count / 5, 2.0)  # Cap at 2x
        
        return int(base_score * count_multiplier)

    def create_hardening_plan(self, findings: List[Dict]) -> Dict:
        """
        Creates comprehensive hardening plan.

        Args:
            findings: List of finding dictionaries

        Returns:
            dict: Hardening plan with phases and timelines
        """
        recommendations = self.generate_recommendations(findings)
        
        # Organize into phases
        immediate_phase = []
        short_term_phase = []
        long_term_phase = []
        
        for rec in recommendations:
            if rec["priority"] >= 60:  # Critical/High priority
                immediate_phase.extend([
                    {"action": action, "family": rec["family"]}
                    for action in rec["immediate_actions"]
                ])
            
            if rec["priority"] >= 30:  # Medium+ priority
                short_term_phase.extend([
                    {"action": action, "family": rec["family"]}
                    for action in rec["short_term_actions"]
                ])
            
            long_term_phase.extend([
                {"action": action, "family": rec["family"]}
                for action in rec["long_term_actions"]
            ])
        
        plan = {
            "summary": {
                "total_findings": len(findings),
                "total_recommendations": len(recommendations),
                "immediate_actions": len(immediate_phase),
                "short_term_actions": len(short_term_phase),
                "long_term_actions": len(long_term_phase)
            },
            "phases": {
                "immediate": {
                    "timeline": "0-7 days",
                    "priority": "critical",
                    "actions": immediate_phase
                },
                "short_term": {
                    "timeline": "1-3 months",
                    "priority": "high",
                    "actions": short_term_phase
                },
                "long_term": {
                    "timeline": "3-12 months",
                    "priority": "medium",
                    "actions": long_term_phase
                }
            },
            "recommendations": recommendations
        }
        
        logger.info("Created hardening plan")
        return plan

    def generate_executive_summary(self, findings: List[Dict]) -> str:
        """
        Generates executive summary of security posture.

        Args:
            findings: List of finding dictionaries

        Returns:
            str: Executive summary text
        """
        total_findings = len(findings)
        
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 5 +
            severity_counts["medium"] * 2 +
            severity_counts["low"] * 1
        )
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 30:
            risk_level = "HIGH"
        elif risk_score >= 15:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        summary = f"""
EXECUTIVE SUMMARY
=================

Security Assessment Results:
- Total Findings: {total_findings}
- Risk Level: {risk_level}
- Risk Score: {risk_score}/100

Findings by Severity:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Informational: {severity_counts['info']}

Immediate Actions Required:
{severity_counts['critical'] + severity_counts['high']} high-priority findings require immediate attention.

Recommendation:
{"Immediate remediation required for critical vulnerabilities." if risk_level in ["CRITICAL", "HIGH"] else "Follow hardening plan to improve security posture."}
"""
        
        return summary.strip()


logger.info("Hardening advisor module loaded")
