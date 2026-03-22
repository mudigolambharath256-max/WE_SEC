"""
Prompt attack runners — Python wrappers for Go probe execution.

This package provides Python orchestration for prompt injection attacks
executed by the Go speed layer. Each runner:
1. Validates scope
2. Loads payloads from corpus
3. Calls Go probe server via gRPC
4. Classifies responses
5. Generates findings

Attack categories:
- Corpus-based attacks (generic prompt injection payloads)
- OOB detection (out-of-band data exfiltration)
- Unicode injection (zero-width, BiDi, homoglyphs)
- RCE probes (LLMSmith patterns)
- FlipAttack (FCS, FCW, FWO variants)
- Adversarial poetry (obfuscated instructions)
- Multilingual attacks (non-English prompts)
- IDOR testing (LLM chain authorization bypass)
- Timing attacks (response timing analysis)
- Environment injection (env var exfiltration)
- Upload path traversal (file upload attacks)

Integration with external tools:
- Augustus (prompt injection framework)
- Garak (LLM vulnerability scanner)
- PyRIT (Red Team toolkit)
- DeepTeam (adversarial testing)
- ArtKit (adversarial robustness toolkit)
- Rigging (agent testing framework)
- Promptfoo (LLM evaluation)
"""
