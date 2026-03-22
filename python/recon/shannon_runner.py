"""
Shannon white-box analysis runner.

Integrates Shannon (https://github.com/dreadnode/shannon) for white-box
vulnerability analysis of AI applications with source code access.

Shannon capabilities:
- Automated vulnerability discovery in LLM applications
- Prompt injection detection in code
- Insecure API usage patterns
- Data flow analysis for sensitive data
- Tool call security analysis

Shannon requires:
- Source code access (white-box testing)
- GitHub repository or local codebase
- GITHUB_TOKEN for private repositories
"""

import os
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class ShannonRunner:
    """
    Shannon white-box analysis runner.

    Runs Shannon vulnerability scanner on AI application source code.

    Args:
        workspace_dir: Directory for Shannon workspace
        github_token: GitHub token for private repos (optional)

    Usage:
        runner = ShannonRunner()
        findings = runner.analyze_repo("https://github.com/org/repo")
    """

    def __init__(
        self,
        workspace_dir: str = "./output/shannon",
        github_token: Optional[str] = None,
    ):
        """Initializes Shannon runner."""
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        
        logger.info(f"Shannon runner initialized: workspace={workspace_dir}")

    def analyze_repo(
        self,
        repo_url: str,
        branch: str = "main",
    ) -> List[Dict[str, Any]]:
        """
        Analyzes GitHub repository with Shannon.

        Args:
            repo_url: GitHub repository URL
            branch: Branch to analyze (default: main)

        Returns:
            List[Dict[str, Any]]: List of findings

        Example:
            findings = runner.analyze_repo("https://github.com/org/ai-app")
            for finding in findings:
                print(f"{finding['severity']}: {finding['title']}")
        """
        logger.info(f"Running Shannon analysis: {repo_url}")
        
        # Clone repository
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_path = self.workspace_dir / repo_name
        
        if not repo_path.exists():
            logger.info(f"Cloning repository: {repo_url}")
            try:
                clone_cmd = ["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(repo_path)]
                if self.github_token:
                    # Inject token into URL for private repos
                    repo_url_with_token = repo_url.replace("https://", f"https://{self.github_token}@")
                    clone_cmd[4] = repo_url_with_token
                
                subprocess.run(clone_cmd, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone repository: {e}")
                return []
        
        # Run Shannon
        findings = self._run_shannon(repo_path)
        
        logger.info(f"Shannon analysis complete: {len(findings)} findings")
        return findings

    def analyze_local(self, code_path: str) -> List[Dict[str, Any]]:
        """
        Analyzes local codebase with Shannon.

        Args:
            code_path: Path to local codebase

        Returns:
            List[Dict[str, Any]]: List of findings

        Example:
            findings = runner.analyze_local("./target_app")
        """
        logger.info(f"Running Shannon analysis on local code: {code_path}")
        
        code_path_obj = Path(code_path)
        if not code_path_obj.exists():
            logger.error(f"Code path not found: {code_path}")
            return []
        
        findings = self._run_shannon(code_path_obj)
        
        logger.info(f"Shannon analysis complete: {len(findings)} findings")
        return findings

    def _run_shannon(self, code_path: Path) -> List[Dict[str, Any]]:
        """
        Runs Shannon scanner on codebase.

        Args:
            code_path: Path to codebase

        Returns:
            List[Dict[str, Any]]: List of findings
        """
        try:
            # Shannon command (placeholder - actual command depends on Shannon CLI)
            cmd = [
                "shannon",
                "scan",
                "--format", "json",
                "--output", str(self.workspace_dir / "shannon_results.json"),
                str(code_path),
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )
            
            if result.returncode != 0:
                logger.warning(f"Shannon returned non-zero exit code: {result.returncode}")
                logger.debug(f"Shannon stderr: {result.stderr}")
            
            # Parse results
            results_file = self.workspace_dir / "shannon_results.json"
            if results_file.exists():
                import json
                with open(results_file) as f:
                    data = json.load(f)
                return data.get("findings", [])
            
            return []
        
        except FileNotFoundError:
            logger.error("Shannon not installed. Install from: https://github.com/dreadnode/shannon")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Shannon timeout (10 minutes)")
            return []
        except Exception as e:
            logger.error(f"Shannon error: {e}")
            return []


logger.info("Shannon runner module loaded")
