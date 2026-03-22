"""
Recon layer — reconnaissance and attack surface mapping.

This package provides reconnaissance capabilities for AI applications:
- triggered_crawler.py: Intelligent web crawler with JavaScript execution
- selenium_fallback.py: Selenium-based fallback for complex SPAs
- stealth.py: Browser fingerprint evasion and anti-detection
- static_analyzer.py: Semgrep-based static analysis
- llmsmith_runner.py: LLMSmith pattern detection
- gguf_template_scanner.py: GGUF model template extraction
- fingerprinter.py: Technology stack fingerprinting
- shodan_enricher.py: Shodan API integration for external recon
- network_binding_checker.py: Network misconfiguration detection
- mcp_detector.py: MCP server detection and enumeration
- mcp_package_auditor.py: MCP package dependency auditing
- supply_chain_scanner.py: Supply chain vulnerability detection
- surface_report.py: Attack surface report generation
- shannon_runner.py: Shannon white-box analysis integration
- vulnhuntr_runner.py: Vulnhuntr LLM-powered vulnerability detection
- xvulnhuntr_runner.py: Extended Vulnhuntr with custom patterns

Recon workflow:
1. Passive reconnaissance (fingerprinting, Shodan, public data)
2. Active reconnaissance (crawling, endpoint discovery)
3. Static analysis (code scanning, dependency auditing)
4. White-box analysis (Shannon, Vulnhuntr for source code access)
5. Attack surface mapping and report generation
"""
