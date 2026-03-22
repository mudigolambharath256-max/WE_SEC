"""
Report generator for llmrt.

Generates comprehensive security reports in multiple formats (HTML, PDF, JSON).
Integrates all framework mappings and remediation guidance.

Usage:
    generator = ReportGenerator()
    report = await generator.generate_report(campaign_id, findings)
    await generator.export_html(report, "output/report.html")
    await generator.export_pdf(report, "output/report.pdf")
"""

import logging
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime
import json
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .mitre_mapper import MITREMapper
from .owasp_llm_mapper import OWASPLLMMapper
from .agentic_owasp_mapper import AgenticOWASPMapper
from .owasp_mcp_top10_mapper import OWASPMCPTop10Mapper
from .adversa_mcp_mapper import AdversaMCPMapper
from .hardening_advisor import HardeningAdvisor

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates comprehensive security reports.

    Integrates all framework mappings and produces multi-format reports.
    """

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initializes report generator.

        Args:
            template_dir: Path to Jinja2 templates directory
        """
        if template_dir is None:
            template_dir = str(Path(__file__).parent / "templates")
        
        self.template_dir = Path(template_dir)
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Initialize mappers
        self.mitre_mapper = MITREMapper()
        self.owasp_llm_mapper = OWASPLLMMapper()
        self.agentic_owasp_mapper = AgenticOWASPMapper()
        self.owasp_mcp_mapper = OWASPMCPTop10Mapper()
        self.adversa_mcp_mapper = AdversaMCPMapper()
        self.hardening_advisor = HardeningAdvisor()
        
        logger.info("Report generator initialized")

    async def generate_report(
        self,
        campaign_id: str,
        findings: List[Dict],
        metadata: Optional[Dict] = None
    ) -> Dict:
        """
        Generates comprehensive security report.

        Args:
            campaign_id: Campaign identifier
            findings: List of finding dictionaries
            metadata: Optional campaign metadata

        Returns:
            dict: Complete report data structure
        """
        logger.info(f"Generating report for campaign {campaign_id}")
        
        # Generate framework mappings
        mitre_mappings = self.mitre_mapper.map_findings(findings)
        mitre_tactics = self.mitre_mapper.get_tactics_summary(findings)
        mitre_attack_path = self.mitre_mapper.get_attack_path(findings)
        
        owasp_llm_mappings = self.owasp_llm_mapper.map_findings(findings)
        owasp_llm_summary = self.owasp_llm_mapper.get_top10_summary(findings)
        owasp_llm_coverage = self.owasp_llm_mapper.get_coverage_report(findings)
        
        agentic_mappings = self.agentic_owasp_mapper.map_findings(findings)
        agent_risk_profile = self.agentic_owasp_mapper.get_agent_risk_profile(findings)
        agent_security_score = self.agentic_owasp_mapper.get_agent_security_score(findings)
        
        owasp_mcp_mappings = self.owasp_mcp_mapper.map_findings(findings)
        owasp_mcp_summary = self.owasp_mcp_mapper.get_mcp_top10_summary(findings)
        
        adversa_mappings = self.adversa_mcp_mapper.map_findings(findings)
        adversa_report = self.adversa_mcp_mapper.get_adversa_top25_report(findings)
        
        # Generate remediation guidance
        recommendations = self.hardening_advisor.generate_recommendations(findings)
        hardening_plan = self.hardening_advisor.create_hardening_plan(findings)
        executive_summary = self.hardening_advisor.generate_executive_summary(findings)
        
        # Calculate statistics
        stats = self._calculate_statistics(findings)
        
        # Build report structure
        report = {
            "metadata": {
                "campaign_id": campaign_id,
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "llmrt v1.0.0",
                "total_findings": len(findings),
                **(metadata or {})
            },
            "executive_summary": executive_summary,
            "statistics": stats,
            "findings": findings,
            "framework_mappings": {
                "mitre": {
                    "mappings": mitre_mappings,
                    "tactics_summary": mitre_tactics,
                    "attack_path": mitre_attack_path
                },
                "owasp_llm": {
                    "mappings": owasp_llm_mappings,
                    "top10_summary": owasp_llm_summary,
                    "coverage": owasp_llm_coverage
                },
                "agentic_owasp": {
                    "mappings": agentic_mappings,
                    "risk_profile": agent_risk_profile,
                    "security_score": agent_security_score
                },
                "owasp_mcp": {
                    "mappings": owasp_mcp_mappings,
                    "top10_summary": owasp_mcp_summary
                },
                "adversa_mcp": {
                    "mappings": adversa_mappings,
                    "top25_report": adversa_report
                }
            },
            "remediation": {
                "recommendations": recommendations,
                "hardening_plan": hardening_plan
            }
        }
        
        logger.info(f"Report generated for campaign {campaign_id}")
        return report

    def _calculate_statistics(self, findings: List[Dict]) -> Dict:
        """Calculates report statistics."""
        stats = {
            "total_findings": len(findings),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "by_family": {},
            "avg_cvss_score": 0.0,
            "max_cvss_score": 0.0
        }
        
        cvss_scores = []
        
        for finding in findings:
            # Count by severity
            severity = finding.get("severity", "info")
            if severity in stats["by_severity"]:
                stats["by_severity"][severity] += 1
            
            # Count by family
            family = finding.get("family", "unknown")
            stats["by_family"][family] = stats["by_family"].get(family, 0) + 1
            
            # Track CVSS scores
            cvss = finding.get("cvss_score")
            if cvss:
                cvss_scores.append(cvss)
        
        # Calculate CVSS statistics
        if cvss_scores:
            stats["avg_cvss_score"] = sum(cvss_scores) / len(cvss_scores)
            stats["max_cvss_score"] = max(cvss_scores)
        
        return stats

    async def export_json(self, report: Dict, output_path: str):
        """
        Exports report as JSON.

        Args:
            report: Report data structure
            output_path: Path to save JSON file

        Raises:
            RuntimeError: If export fails
        """
        logger.info(f"Exporting JSON report to {output_path}")
        
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"JSON report exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export JSON report: {e}")
            raise RuntimeError(f"JSON export failed: {e}")

    async def export_html(self, report: Dict, output_path: str):
        """
        Exports report as HTML.

        Args:
            report: Report data structure
            output_path: Path to save HTML file

        Raises:
            RuntimeError: If export fails
        """
        logger.info(f"Exporting HTML report to {output_path}")
        
        try:
            # Load template
            template = self.jinja_env.get_template("report.html.jinja")
            
            # Render template
            html_content = template.render(report=report)
            
            # Save to file
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            logger.info(f"HTML report exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export HTML report: {e}")
            raise RuntimeError(f"HTML export failed: {e}")

    async def export_pdf(self, report: Dict, output_path: str):
        """
        Exports report as PDF.

        Args:
            report: Report data structure
            output_path: Path to save PDF file

        Raises:
            RuntimeError: If export fails
        """
        logger.info(f"Exporting PDF report to {output_path}")
        
        try:
            from weasyprint import HTML, CSS
            
            # Generate HTML first
            template = self.jinja_env.get_template("report.html.jinja")
            html_content = template.render(report=report)
            
            # Convert to PDF
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            HTML(string=html_content).write_pdf(
                output_file,
                stylesheets=[CSS(string=self._get_pdf_styles())]
            )
            
            logger.info(f"PDF report exported to {output_path}")
            
        except ImportError:
            logger.error("weasyprint not installed. Install with: pip install weasyprint")
            raise RuntimeError("PDF export requires weasyprint package")
        except Exception as e:
            logger.error(f"Failed to export PDF report: {e}")
            raise RuntimeError(f"PDF export failed: {e}")

    def _get_pdf_styles(self) -> str:
        """Returns CSS styles for PDF generation."""
        return """
        @page {
            size: A4;
            margin: 2cm;
        }
        body {
            font-family: Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.5;
        }
        h1 {
            font-size: 18pt;
            color: #333;
            page-break-before: always;
        }
        h1:first-of-type {
            page-break-before: avoid;
        }
        h2 {
            font-size: 14pt;
            color: #555;
            margin-top: 1em;
        }
        h3 {
            font-size: 12pt;
            color: #777;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1em 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        .critical {
            color: #d32f2f;
            font-weight: bold;
        }
        .high {
            color: #f57c00;
            font-weight: bold;
        }
        .medium {
            color: #fbc02d;
        }
        .low {
            color: #388e3c;
        }
        """

    async def export_markdown(self, report: Dict, output_path: str):
        """
        Exports report as Markdown.

        Args:
            report: Report data structure
            output_path: Path to save Markdown file

        Raises:
            RuntimeError: If export fails
        """
        logger.info(f"Exporting Markdown report to {output_path}")
        
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Build Markdown content
            md_content = self._build_markdown(report)
            
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(md_content)
            
            logger.info(f"Markdown report exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export Markdown report: {e}")
            raise RuntimeError(f"Markdown export failed: {e}")

    def _build_markdown(self, report: Dict) -> str:
        """Builds Markdown content from report."""
        metadata = report["metadata"]
        stats = report["statistics"]
        
        md = f"""# Security Assessment Report

**Campaign ID:** {metadata['campaign_id']}  
**Generated:** {metadata['generated_at']}  
**Total Findings:** {metadata['total_findings']}

## Executive Summary

{report['executive_summary']}

## Statistics

### Findings by Severity
- Critical: {stats['by_severity']['critical']}
- High: {stats['by_severity']['high']}
- Medium: {stats['by_severity']['medium']}
- Low: {stats['by_severity']['low']}
- Info: {stats['by_severity']['info']}

### CVSS Scores
- Average: {stats['avg_cvss_score']:.1f}
- Maximum: {stats['max_cvss_score']:.1f}

## Framework Mappings

### MITRE ATT&CK
{len(report['framework_mappings']['mitre']['mappings'])} findings mapped to MITRE techniques.

### OWASP LLM Top 10
Coverage: {report['framework_mappings']['owasp_llm']['coverage']['coverage_percentage']:.1f}%

### Agent Security Score
Score: {report['framework_mappings']['agentic_owasp']['security_score']['score']}/100  
Grade: {report['framework_mappings']['agentic_owasp']['security_score']['grade']}

## Remediation

### Immediate Actions
{len(report['remediation']['hardening_plan']['phases']['immediate']['actions'])} actions required within 0-7 days.

### Short-Term Actions
{len(report['remediation']['hardening_plan']['phases']['short_term']['actions'])} actions required within 1-3 months.

### Long-Term Actions
{len(report['remediation']['hardening_plan']['phases']['long_term']['actions'])} actions required within 3-12 months.

---
*Generated by llmrt v1.0.0*
"""
        return md


logger.info("Report generator module loaded")
