"""
Semgrep-based static analysis for AI applications.

Runs Semgrep rules to detect security vulnerabilities in source code:
- Prompt injection vulnerabilities
- Insecure LLM API usage
- Hardcoded API keys and secrets
- SQL injection in RAG queries
- Path traversal in document loaders
- Insecure deserialization
- Command injection in tool calls

Uses custom Semgrep rules from data/semgrep_rules/ plus community rules.

Static analysis is only available when source code access is provided
(white-box testing). For black-box testing, use dynamic probing instead.
"""

import os
import json
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class StaticFinding:
    """
    Represents a static analysis finding.

    Attributes:
        rule_id: Semgrep rule identifier
        severity: error | warning | info
        message: Finding message
        file_path: Path to vulnerable file
        line_number: Line number of vulnerability
        code_snippet: Code snippet showing vulnerability
        fix: Suggested fix (if available)
    """
    rule_id: str
    severity: str
    message: str
    file_path: str
    line_number: int
    code_snippet: str
    fix: Optional[str] = None


class StaticAnalyzer:
    """
    Semgrep-based static analysis for AI applications.

    Runs Semgrep rules to detect security vulnerabilities in source code.

    Args:
        rules_path: Path to custom Semgrep rules directory
        target_path: Path to target codebase

    Usage:
        analyzer = StaticAnalyzer(
            rules_path="./data/semgrep_rules",
            target_path="./target_app",
        )
        findings = analyzer.analyze()
        print(f"Found {len(findings)} vulnerabilities")
    """

    def __init__(
        self,
        rules_path: str = "./data/semgrep_rules",
        target_path: str = "./target_app",
    ):
        """Initializes static analyzer."""
        self.rules_path = Path(rules_path)
        self.target_path = Path(target_path)
        
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path not found: {target_path}")
        
        logger.info(f"Static analyzer initialized: target={target_path}")

    def analyze(self, rule_ids: Optional[List[str]] = None) -> List[StaticFinding]:
        """
        Runs static analysis on target codebase.

        Args:
            rule_ids: List of specific rule IDs to run (optional, runs all if not provided)

        Returns:
            List[StaticFinding]: List of static analysis findings

        Example:
            findings = analyzer.analyze()
            for finding in findings:
                print(f"{finding.severity}: {finding.message} at {finding.file_path}:{finding.line_number}")
        """
        logger.info(f"Running static analysis on {self.target_path}")
        
        # Build Semgrep command
        cmd = ["semgrep", "--json", "--quiet"]
        
        if self.rules_path.exists():
            cmd.extend(["--config", str(self.rules_path)])
        else:
            logger.warning(f"Rules path not found: {self.rules_path}, using default rules")
            cmd.extend(["--config", "auto"])
        
        if rule_ids:
            for rule_id in rule_ids:
                cmd.extend(["--include", rule_id])
        
        cmd.append(str(self.target_path))
        
        try:
            # Run Semgrep
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            
            if result.returncode not in [0, 1]:  # 0 = no findings, 1 = findings found
                logger.error(f"Semgrep error: {result.stderr}")
                return []
            
            # Parse results
            output = json.loads(result.stdout)
            findings = self._parse_semgrep_output(output)
            
            logger.info(f"Static analysis complete: {len(findings)} findings")
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error("Semgrep timeout (5 minutes)")
            return []
        except FileNotFoundError:
            logger.error("Semgrep not installed. Install with: pip install semgrep")
            return []
        except Exception as e:
            logger.error(f"Static analysis error: {e}")
            return []

    def _parse_semgrep_output(self, output: Dict[str, Any]) -> List[StaticFinding]:
        """
        Parses Semgrep JSON output into StaticFinding objects.

        Args:
            output: Semgrep JSON output

        Returns:
            List[StaticFinding]: Parsed findings
        """
        findings = []
        
        for result in output.get("results", []):
            finding = StaticFinding(
                rule_id=result.get("check_id", "unknown"),
                severity=result.get("extra", {}).get("severity", "info"),
                message=result.get("extra", {}).get("message", "No message"),
                file_path=result.get("path", "unknown"),
                line_number=result.get("start", {}).get("line", 0),
                code_snippet=result.get("extra", {}).get("lines", ""),
                fix=result.get("extra", {}).get("fix", None),
            )
            findings.append(finding)
        
        return findings

    def analyze_llm_specific(self) -> List[StaticFinding]:
        """
        Runs LLM-specific static analysis rules.

        Returns:
            List[StaticFinding]: LLM-specific findings

        Example:
            findings = analyzer.analyze_llm_specific()
        """
        llm_rule_ids = [
            "prompt-injection",
            "insecure-llm-api",
            "hardcoded-api-key",
            "sql-injection-rag",
            "path-traversal-loader",
            "command-injection-tool",
        ]
        
        return self.analyze(rule_ids=llm_rule_ids)

    def generate_report(self, findings: List[StaticFinding]) -> str:
        """
        Generates human-readable static analysis report.

        Args:
            findings: List of static findings

        Returns:
            str: Formatted report

        Example:
            report = analyzer.generate_report(findings)
            print(report)
        """
        if not findings:
            return "No static analysis findings detected."
        
        lines = ["Static Analysis Report", "=" * 60, ""]
        
        # Group by severity
        by_severity = {"error": [], "warning": [], "info": []}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(finding)
        
        for severity in ["error", "warning", "info"]:
            severity_findings = by_severity[severity]
            if not severity_findings:
                continue
            
            lines.append(f"{severity.upper()}: {len(severity_findings)} findings")
            lines.append("-" * 60)
            
            for finding in severity_findings:
                lines.append(f"Rule: {finding.rule_id}")
                lines.append(f"File: {finding.file_path}:{finding.line_number}")
                lines.append(f"Message: {finding.message}")
                lines.append(f"Code: {finding.code_snippet[:100]}...")
                if finding.fix:
                    lines.append(f"Fix: {finding.fix}")
                lines.append("")
        
        lines.append("=" * 60)
        lines.append(f"Total: {len(findings)} findings")
        
        return "\n".join(lines)


logger.info("Static analyzer module loaded")
