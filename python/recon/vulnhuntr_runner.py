"""
Vulnhuntr LLM-powered vulnerability detection.

Integrates Vulnhuntr (https://github.com/protectai/vulnhuntr) for
LLM-powered static analysis of Python codebases.

Vulnhuntr uses Claude to analyze code for:
- SQL injection
- Path traversal
- Command injection
- Insecure deserialization
- Authentication bypasses
- Authorization flaws

Requires:
- ANTHROPIC_API_KEY environment variable
- Python codebase with source access
"""

import os
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class VulnhuntrRunner:
    """
    Vulnhuntr LLM-powered vulnerability detection.

    Uses Claude to analyze Python code for security vulnerabilities.

    Args:
        model: Claude model to use (default: claude-sonnet-4)
        venv_path: Path to Vulnhuntr virtual environment

    Usage:
        runner = VulnhuntrRunner()
        findings = runner.analyze("./target_app")
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4",
        venv_path: str = "./venv_vulnhuntr",
    ):
        """Initializes Vulnhuntr runner."""
        self.model = model
        self.venv_path = Path(venv_path)
        
        # Check for API key
        if not os.getenv("ANTHROPIC_API_KEY"):
            logger.warning("ANTHROPIC_API_KEY not set, Vulnhuntr will fail")
        
        logger.info(f"Vulnhuntr runner initialized: model={model}")

    def analyze(
        self,
        code_path: str,
        root_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Analyzes Python codebase with Vulnhuntr.

        Args:
            code_path: Path to Python file or directory
            root_path: Root path for relative imports (optional)

        Returns:
            List[Dict[str, Any]]: List of findings

        Example:
            findings = runner.analyze("./target_app/main.py")
            for finding in findings:
                print(f"{finding['type']}: {finding['description']}")
        """
        logger.info(f"Running Vulnhuntr analysis: {code_path}")
        
        code_path_obj = Path(code_path)
        if not code_path_obj.exists():
            logger.error(f"Code path not found: {code_path}")
            return []
        
        try:
            # Build Vulnhuntr command
            cmd = [
                "vulnhuntr",
                "--model", self.model,
                "--json",
                str(code_path),
            ]
            
            if root_path:
                cmd.extend(["--root", root_path])
            
            # Run Vulnhuntr
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900,  # 15 minute timeout (LLM analysis is slow)
                env={**os.environ, "VULNHUNTR_MODEL": self.model},
            )
            
            if result.returncode != 0:
                logger.warning(f"Vulnhuntr returned non-zero exit code: {result.returncode}")
                logger.debug(f"Vulnhuntr stderr: {result.stderr}")
            
            # Parse JSON output
            import json
            findings = json.loads(result.stdout)
            
            logger.info(f"Vulnhuntr analysis complete: {len(findings)} findings")
            return findings
        
        except FileNotFoundError:
            logger.error("Vulnhuntr not installed. Install with: pip install vulnhuntr")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Vulnhuntr timeout (15 minutes)")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Vulnhuntr output: {e}")
            return []
        except Exception as e:
            logger.error(f"Vulnhuntr error: {e}")
            return []

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyzes single Python file with Vulnhuntr.

        Args:
            file_path: Path to Python file

        Returns:
            List[Dict[str, Any]]: List of findings
        """
        return self.analyze(file_path)

    def analyze_directory(
        self,
        dir_path: str,
        extensions: List[str] = [".py"],
    ) -> List[Dict[str, Any]]:
        """
        Analyzes all Python files in directory with Vulnhuntr.

        Args:
            dir_path: Path to directory
            extensions: File extensions to analyze (default: [".py"])

        Returns:
            List[Dict[str, Any]]: List of findings from all files
        """
        logger.info(f"Running Vulnhuntr on directory: {dir_path}")
        
        dir_path_obj = Path(dir_path)
        if not dir_path_obj.exists():
            logger.error(f"Directory not found: {dir_path}")
            return []
        
        all_findings = []
        
        # Find all Python files
        for ext in extensions:
            for file_path in dir_path_obj.rglob(f"*{ext}"):
                logger.debug(f"Analyzing file: {file_path}")
                findings = self.analyze(str(file_path), root_path=str(dir_path_obj))
                all_findings.extend(findings)
        
        logger.info(f"Vulnhuntr directory analysis complete: {len(all_findings)} findings")
        return all_findings


logger.info("Vulnhuntr runner module loaded")
