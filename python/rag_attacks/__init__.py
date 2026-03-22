"""
RAG (Retrieval-Augmented Generation) attack runners.

This package provides attack modules for RAG-based AI applications:
- llamator_runner.py: Llamator RAG security testing
- doc_injector.py: Malicious document injection
- code_file_injector.py: Code file poisoning
- stored_prompt_injector.py: Persistent prompt injection via documents
- vector_db_attacker.py: Vector database manipulation
- memory_poison_tester.py: Agent memory poisoning
- context_monitor.py: Context window monitoring and analysis

RAG-specific vulnerabilities:
- Document poisoning (injecting malicious content into knowledge base)
- Context manipulation (controlling retrieved context)
- Memory poisoning (corrupting agent memory)
- Vector database attacks (similarity search manipulation)
- Stored prompt injection (persistent attacks via documents)
"""
