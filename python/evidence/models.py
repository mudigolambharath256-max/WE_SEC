"""
SQLAlchemy ORM models for evidence storage.

Defines the database schema for campaigns, sessions, findings, and metadata.
All tables use SQLCipher encryption via pysqlcipher3.

Schema design principles:
- Every finding links to a campaign and session
- Findings are immutable once created (append-only)
- Deduplication hash stored for fast duplicate detection
- CVSS scores stored as JSON for full vector preservation
- Verification status tracked through 4-layer pipeline
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()


class Campaign(Base):
    """
    Represents a complete security assessment campaign.

    A campaign is the top-level container for all testing activity against
    a target. It tracks scope, configuration, and overall status.

    Attributes:
        id: Primary key
        campaign_id: Unique identifier (UUID)
        target_url: Primary target URL
        target_type: chatbot | rag_app | mcp_agent | ide_assistant
        scope_hash: SHA256 of scope.yaml (detects scope changes)
        started_at: Campaign start timestamp
        completed_at: Campaign completion timestamp (null if running)
        status: queued | running | completed | failed | cancelled
        config: JSON blob of campaign configuration
        findings_count: Cached count of findings (updated on insert)
        critical_count: Cached count of critical findings
        high_count: Cached count of high findings
    """
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(String(64), unique=True, nullable=False, index=True)
    target_url = Column(String(512), nullable=False)
    target_type = Column(String(32), nullable=False)
    scope_hash = Column(String(64), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(16), default="queued", nullable=False)
    config = Column(JSON, nullable=True)
    findings_count = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)

    # Relationships
    sessions = relationship("Session", back_populates="campaign", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="campaign", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Campaign {self.campaign_id} {self.status} findings={self.findings_count}>"


class Session(Base):
    """
    Represents a single attack session within a campaign.

    A session is a logical grouping of related probes (e.g., all prompt
    injection tests, all MCP enumeration, etc.). Sessions run sequentially
    or in parallel depending on campaign configuration.

    Attributes:
        id: Primary key
        session_id: Unique identifier (UUID)
        campaign_id: Foreign key to parent campaign
        session_type: prompt_injection | rag_attack | mcp_attack | recon | etc.
        started_at: Session start timestamp
        completed_at: Session completion timestamp
        status: running | completed | failed | cancelled
        probes_sent: Total number of probes sent
        responses_received: Total responses received
        findings_count: Number of findings generated in this session
        error_message: Error details if status=failed
    """
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    campaign_id = Column(String(64), ForeignKey("campaigns.campaign_id"), nullable=False, index=True)
    session_type = Column(String(64), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(16), default="running", nullable=False)
    probes_sent = Column(Integer, default=0, nullable=False)
    responses_received = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)

    # Relationships
    campaign = relationship("Campaign", back_populates="sessions")
    findings = relationship("Finding", back_populates="session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Session {self.session_id} {self.session_type} {self.status}>"


class Finding(Base):
    """
    Represents a single security finding.

    Findings are immutable once created. All fields are populated at creation
    time and never modified. Updates create new finding records.

    Attributes:
        id: Primary key
        finding_id: Unique identifier (UUID)
        campaign_id: Foreign key to parent campaign
        session_id: Foreign key to parent session
        finding_family: Normalized family name (from FAMILY_MAP)
        finding_type: Specific finding type (e.g., prompt_injection_jailbreak)
        severity: critical | high | medium | low | info
        cvss_score: CVSS 4.0 base score (0.0-10.0)
        cvss_vector: Full CVSS 4.0 vector string
        title: Short finding title
        description: Detailed finding description
        payload: The probe payload that triggered this finding
        response: The target's response (truncated to 10KB)
        evidence: Additional evidence (screenshots, logs, etc.) as JSON
        remediation: Remediation guidance
        references: List of reference URLs as JSON
        oob_callback: True if finding confirmed via OOB callback
        verified: True if passed all 4 verification layers
        false_positive: True if flagged as false positive
        duplicate_of: finding_id of original if this is a duplicate
        dedup_hash: ssdeep fuzzy hash for duplicate detection
        created_at: Finding creation timestamp
        mitre_tactics: MITRE ATT&CK tactics as JSON list
        owasp_categories: OWASP LLM Top 10 categories as JSON list
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(64), unique=True, nullable=False, index=True)
    campaign_id = Column(String(64), ForeignKey("campaigns.campaign_id"), nullable=False, index=True)
    session_id = Column(String(64), ForeignKey("sessions.session_id"), nullable=False, index=True)
    finding_family = Column(String(64), nullable=False, index=True)
    finding_type = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    cvss_score = Column(Float, nullable=False, index=True)
    cvss_vector = Column(String(256), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    payload = Column(Text, nullable=False)
    response = Column(Text, nullable=False)  # Truncated to 10KB
    evidence = Column(JSON, nullable=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)
    oob_callback = Column(Boolean, default=False, nullable=False)
    verified = Column(Boolean, default=False, nullable=False, index=True)
    false_positive = Column(Boolean, default=False, nullable=False, index=True)
    duplicate_of = Column(String(64), nullable=True, index=True)
    dedup_hash = Column(String(128), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    mitre_tactics = Column(JSON, nullable=True)
    owasp_categories = Column(JSON, nullable=True)

    # Relationships
    campaign = relationship("Campaign", back_populates="findings")
    session = relationship("Session", back_populates="findings")

    def __repr__(self):
        return f"<Finding {self.finding_id} {self.severity} {self.finding_family}>"

    def to_dict(self):
        """
        Converts finding to dictionary for JSON serialization.

        Returns:
            dict: Finding data with all fields
        """
        return {
            "finding_id": self.finding_id,
            "campaign_id": self.campaign_id,
            "session_id": self.session_id,
            "finding_family": self.finding_family,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "title": self.title,
            "description": self.description,
            "payload": self.payload,
            "response": self.response[:1000] + "..." if len(self.response) > 1000 else self.response,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "oob_callback": self.oob_callback,
            "verified": self.verified,
            "false_positive": self.false_positive,
            "duplicate_of": self.duplicate_of,
            "created_at": self.created_at.isoformat(),
            "mitre_tactics": self.mitre_tactics,
            "owasp_categories": self.owasp_categories,
        }


class OOBCallback(Base):
    """
    Represents an out-of-band callback received from Interactsh.

    OOB callbacks provide definitive proof of certain vulnerability classes
    (SSRF, RCE, data exfiltration). They are correlated with findings by
    matching callback_id to payload markers.

    Attributes:
        id: Primary key
        callback_id: Unique callback identifier from Interactsh
        campaign_id: Foreign key to parent campaign
        session_id: Foreign key to parent session (if known)
        finding_id: Foreign key to associated finding (if correlated)
        protocol: http | dns | smtp | etc.
        source_ip: IP address of callback source
        received_at: Callback receipt timestamp
        raw_data: Full callback data as JSON
        correlated: True if successfully matched to a finding
    """
    __tablename__ = "oob_callbacks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    callback_id = Column(String(128), unique=True, nullable=False, index=True)
    campaign_id = Column(String(64), ForeignKey("campaigns.campaign_id"), nullable=False, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    finding_id = Column(String(64), nullable=True, index=True)
    protocol = Column(String(16), nullable=False)
    source_ip = Column(String(64), nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    raw_data = Column(JSON, nullable=False)
    correlated = Column(Boolean, default=False, nullable=False, index=True)

    def __repr__(self):
        return f"<OOBCallback {self.callback_id} {self.protocol} correlated={self.correlated}>"


logger.info("Evidence models loaded: Campaign, Session, Finding, OOBCallback")
