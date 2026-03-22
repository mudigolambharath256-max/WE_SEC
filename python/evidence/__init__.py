"""
Evidence layer — encrypted storage, scoring, deduplication, and verification.

This package handles all finding persistence and quality assurance:
- models.py: SQLAlchemy ORM models for findings, campaigns, sessions
- store.py: SQLCipher encrypted database operations
- scorer.py: CVSS 4.0 scoring engine
- deduplicator.py: ssdeep fuzzy hashing for duplicate detection
- verifier.py: 4-layer false positive pipeline

All evidence is encrypted at rest using SQLCipher. The encryption key
must be provided via CAMPAIGN_ENCRYPT_KEY environment variable.

Never store findings in plaintext. Never skip verification.
"""
