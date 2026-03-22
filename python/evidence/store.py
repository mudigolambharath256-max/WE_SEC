"""
SQLCipher encrypted evidence store.

Provides thread-safe database operations for campaigns, sessions, and findings.
All data is encrypted at rest using SQLCipher via pysqlcipher3.

The encryption key MUST be provided via CAMPAIGN_ENCRYPT_KEY environment
variable. Never hardcode keys. Never store findings in plaintext.

Usage:
    store = EvidenceStore(db_path="./output/findings.db")
    campaign_id = store.create_campaign(target_url="https://example.com", ...)
    finding_id = store.insert_finding(campaign_id=campaign_id, ...)
    findings = store.get_findings(campaign_id=campaign_id, severity="critical")
"""

import os
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
from datetime import datetime
import hashlib
import uuid

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from .models import Base, Campaign, Session as SessionModel, Finding, OOBCallback

logger = logging.getLogger(__name__)


class EvidenceStoreError(Exception):
    """Raised when evidence store operations fail."""
    pass


class EvidenceStore:
    """
    Thread-safe SQLCipher encrypted evidence store.

    Handles all database operations for campaigns, sessions, findings, and
    OOB callbacks. Automatically manages encryption, connection pooling,
    and transaction handling.

    Args:
        db_path: Path to SQLCipher database file
        encryption_key: Encryption key (defaults to CAMPAIGN_ENCRYPT_KEY env var)

    Raises:
        EvidenceStoreError: If encryption key not provided or database init fails
    """

    def __init__(self, db_path: str = "./output/findings.db", encryption_key: Optional[str] = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Get encryption key from environment or parameter
        self.encryption_key = encryption_key or os.getenv("CAMPAIGN_ENCRYPT_KEY")
        if not self.encryption_key:
            raise EvidenceStoreError(
                "CAMPAIGN_ENCRYPT_KEY environment variable not set. "
                "Evidence must be encrypted. Set this variable before running campaigns."
            )

        # Create SQLCipher engine
        # Use pysqlcipher3 driver with encryption pragma
        db_url = f"sqlite+pysqlcipher:///{self.db_path.absolute()}"
        
        self.engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )

        # Set encryption key on every connection
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute(f"PRAGMA key = '{self.encryption_key}'")
            cursor.execute("PRAGMA cipher_page_size = 4096")
            cursor.execute("PRAGMA kdf_iter = 256000")
            cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
            cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
            cursor.close()

        # Create tables
        try:
            Base.metadata.create_all(self.engine)
            logger.info(f"Evidence store initialized: {self.db_path} (encrypted)")
        except Exception as e:
            raise EvidenceStoreError(f"Failed to initialize evidence store: {e}")

        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    @contextmanager
    def get_session(self):
        """
        Context manager for database sessions.

        Yields:
            Session: SQLAlchemy session

        Raises:
            EvidenceStoreError: If session creation or commit fails
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise EvidenceStoreError(f"Database operation failed: {e}")
        finally:
            session.close()

    def create_campaign(
        self,
        target_url: str,
        target_type: str,
        scope_yaml_path: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Creates a new campaign record.

        Args:
            target_url: Primary target URL
            target_type: chatbot | rag_app | mcp_agent | ide_assistant
            scope_yaml_path: Path to scope.yaml file
            config: Campaign configuration dictionary

        Returns:
            str: campaign_id (UUID)

        Raises:
            EvidenceStoreError: If campaign creation fails
        """
        campaign_id = str(uuid.uuid4())
        
        # Hash scope.yaml for change detection
        scope_content = Path(scope_yaml_path).read_bytes()
        scope_hash = hashlib.sha256(scope_content).hexdigest()

        with self.get_session() as session:
            campaign = Campaign(
                campaign_id=campaign_id,
                target_url=target_url,
                target_type=target_type,
                scope_hash=scope_hash,
                status="queued",
                config=config or {},
            )
            session.add(campaign)
            logger.info(f"Campaign created: {campaign_id} target={target_url}")

        return campaign_id

    def update_campaign_status(self, campaign_id: str, status: str, completed_at: Optional[datetime] = None):
        """
        Updates campaign status.

        Args:
            campaign_id: Campaign UUID
            status: queued | running | completed | failed | cancelled
            completed_at: Completion timestamp (optional)

        Raises:
            EvidenceStoreError: If campaign not found or update fails
        """
        with self.get_session() as session:
            campaign = session.query(Campaign).filter_by(campaign_id=campaign_id).first()
            if not campaign:
                raise EvidenceStoreError(f"Campaign not found: {campaign_id}")
            
            campaign.status = status
            if completed_at:
                campaign.completed_at = completed_at
            
            logger.info(f"Campaign {campaign_id} status updated: {status}")

    def create_session(
        self,
        campaign_id: str,
        session_type: str,
    ) -> str:
        """
        Creates a new session record.

        Args:
            campaign_id: Parent campaign UUID
            session_type: prompt_injection | rag_attack | mcp_attack | recon | etc.

        Returns:
            str: session_id (UUID)

        Raises:
            EvidenceStoreError: If session creation fails
        """
        session_id = str(uuid.uuid4())

        with self.get_session() as session:
            session_record = SessionModel(
                session_id=session_id,
                campaign_id=campaign_id,
                session_type=session_type,
                status="running",
            )
            session.add(session_record)
            logger.info(f"Session created: {session_id} type={session_type}")

        return session_id

    def update_session_stats(
        self,
        session_id: str,
        probes_sent: Optional[int] = None,
        responses_received: Optional[int] = None,
        status: Optional[str] = None,
        error_message: Optional[str] = None,
    ):
        """
        Updates session statistics.

        Args:
            session_id: Session UUID
            probes_sent: Total probes sent (optional)
            responses_received: Total responses received (optional)
            status: running | completed | failed | cancelled (optional)
            error_message: Error details if status=failed (optional)

        Raises:
            EvidenceStoreError: If session not found or update fails
        """
        with self.get_session() as session:
            session_record = session.query(SessionModel).filter_by(session_id=session_id).first()
            if not session_record:
                raise EvidenceStoreError(f"Session not found: {session_id}")
            
            if probes_sent is not None:
                session_record.probes_sent = probes_sent
            if responses_received is not None:
                session_record.responses_received = responses_received
            if status:
                session_record.status = status
                if status in ["completed", "failed", "cancelled"]:
                    session_record.completed_at = datetime.utcnow()
            if error_message:
                session_record.error_message = error_message

    def insert_finding(
        self,
        campaign_id: str,
        session_id: str,
        finding_family: str,
        finding_type: str,
        severity: str,
        cvss_score: float,
        cvss_vector: str,
        title: str,
        description: str,
        payload: str,
        response: str,
        dedup_hash: str,
        evidence: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        oob_callback: bool = False,
        verified: bool = False,
        mitre_tactics: Optional[List[str]] = None,
        owasp_categories: Optional[List[str]] = None,
    ) -> str:
        """
        Inserts a new finding record.

        Args:
            campaign_id: Parent campaign UUID
            session_id: Parent session UUID
            finding_family: Normalized family name (from FAMILY_MAP)
            finding_type: Specific finding type
            severity: critical | high | medium | low | info
            cvss_score: CVSS 4.0 base score (0.0-10.0)
            cvss_vector: Full CVSS 4.0 vector string
            title: Short finding title
            description: Detailed finding description
            payload: The probe payload that triggered this finding
            response: The target's response (will be truncated to 10KB)
            dedup_hash: ssdeep fuzzy hash for duplicate detection
            evidence: Additional evidence dictionary (optional)
            remediation: Remediation guidance (optional)
            references: List of reference URLs (optional)
            oob_callback: True if confirmed via OOB callback (optional)
            verified: True if passed all 4 verification layers (optional)
            mitre_tactics: MITRE ATT&CK tactics list (optional)
            owasp_categories: OWASP LLM Top 10 categories list (optional)

        Returns:
            str: finding_id (UUID)

        Raises:
            EvidenceStoreError: If finding insertion fails
        """
        finding_id = str(uuid.uuid4())

        # Truncate response to 10KB
        max_response_len = 10 * 1024
        if len(response) > max_response_len:
            response = response[:max_response_len] + "\n[TRUNCATED]"

        with self.get_session() as session:
            finding = Finding(
                finding_id=finding_id,
                campaign_id=campaign_id,
                session_id=session_id,
                finding_family=finding_family,
                finding_type=finding_type,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                title=title,
                description=description,
                payload=payload,
                response=response,
                dedup_hash=dedup_hash,
                evidence=evidence,
                remediation=remediation,
                references=references,
                oob_callback=oob_callback,
                verified=verified,
                mitre_tactics=mitre_tactics,
                owasp_categories=owasp_categories,
            )
            session.add(finding)

            # Update campaign counters
            campaign = session.query(Campaign).filter_by(campaign_id=campaign_id).first()
            if campaign:
                campaign.findings_count += 1
                if severity == "critical":
                    campaign.critical_count += 1
                elif severity == "high":
                    campaign.high_count += 1

            # Update session counter
            session_record = session.query(SessionModel).filter_by(session_id=session_id).first()
            if session_record:
                session_record.findings_count += 1

            logger.info(f"Finding inserted: {finding_id} {severity} {finding_family}")

        return finding_id

    def mark_duplicate(self, finding_id: str, duplicate_of: str):
        """
        Marks a finding as a duplicate of another finding.

        Args:
            finding_id: Finding UUID to mark as duplicate
            duplicate_of: Original finding UUID

        Raises:
            EvidenceStoreError: If finding not found or update fails
        """
        with self.get_session() as session:
            finding = session.query(Finding).filter_by(finding_id=finding_id).first()
            if not finding:
                raise EvidenceStoreError(f"Finding not found: {finding_id}")
            
            finding.duplicate_of = duplicate_of
            logger.info(f"Finding {finding_id} marked as duplicate of {duplicate_of}")

    def mark_false_positive(self, finding_id: str):
        """
        Marks a finding as a false positive.

        Args:
            finding_id: Finding UUID

        Raises:
            EvidenceStoreError: If finding not found or update fails
        """
        with self.get_session() as session:
            finding = session.query(Finding).filter_by(finding_id=finding_id).first()
            if not finding:
                raise EvidenceStoreError(f"Finding not found: {finding_id}")
            
            finding.false_positive = True
            logger.info(f"Finding {finding_id} marked as false positive")

    def mark_verified(self, finding_id: str):
        """
        Marks a finding as verified (passed all 4 verification layers).

        Args:
            finding_id: Finding UUID

        Raises:
            EvidenceStoreError: If finding not found or update fails
        """
        with self.get_session() as session:
            finding = session.query(Finding).filter_by(finding_id=finding_id).first()
            if not finding:
                raise EvidenceStoreError(f"Finding not found: {finding_id}")
            
            finding.verified = True
            logger.info(f"Finding {finding_id} marked as verified")

    def get_findings(
        self,
        campaign_id: str,
        severity: Optional[str] = None,
        verified_only: bool = False,
        exclude_duplicates: bool = True,
        exclude_false_positives: bool = True,
    ) -> List[Finding]:
        """
        Retrieves findings for a campaign with optional filters.

        Args:
            campaign_id: Campaign UUID
            severity: Filter by severity (optional)
            verified_only: Only return verified findings (optional)
            exclude_duplicates: Exclude duplicate findings (optional)
            exclude_false_positives: Exclude false positives (optional)

        Returns:
            List[Finding]: List of finding records

        Raises:
            EvidenceStoreError: If query fails
        """
        with self.get_session() as session:
            query = session.query(Finding).filter_by(campaign_id=campaign_id)
            
            if severity:
                query = query.filter_by(severity=severity)
            if verified_only:
                query = query.filter_by(verified=True)
            if exclude_duplicates:
                query = query.filter(Finding.duplicate_of.is_(None))
            if exclude_false_positives:
                query = query.filter_by(false_positive=False)
            
            findings = query.order_by(Finding.cvss_score.desc()).all()
            logger.info(f"Retrieved {len(findings)} findings for campaign {campaign_id}")
            return findings

    def insert_oob_callback(
        self,
        callback_id: str,
        campaign_id: str,
        protocol: str,
        source_ip: str,
        raw_data: Dict[str, Any],
        session_id: Optional[str] = None,
    ) -> int:
        """
        Inserts an OOB callback record.

        Args:
            callback_id: Unique callback identifier from Interactsh
            campaign_id: Parent campaign UUID
            protocol: http | dns | smtp | etc.
            source_ip: IP address of callback source
            raw_data: Full callback data dictionary
            session_id: Parent session UUID (optional)

        Returns:
            int: OOB callback database ID

        Raises:
            EvidenceStoreError: If insertion fails
        """
        with self.get_session() as session:
            callback = OOBCallback(
                callback_id=callback_id,
                campaign_id=campaign_id,
                session_id=session_id,
                protocol=protocol,
                source_ip=source_ip,
                raw_data=raw_data,
            )
            session.add(callback)
            session.flush()
            callback_db_id = callback.id
            logger.info(f"OOB callback inserted: {callback_id} {protocol} from {source_ip}")

        return callback_db_id

    def correlate_oob_callback(self, callback_id: str, finding_id: str):
        """
        Correlates an OOB callback with a finding.

        Args:
            callback_id: Callback identifier
            finding_id: Finding UUID

        Raises:
            EvidenceStoreError: If callback or finding not found
        """
        with self.get_session() as session:
            callback = session.query(OOBCallback).filter_by(callback_id=callback_id).first()
            if not callback:
                raise EvidenceStoreError(f"OOB callback not found: {callback_id}")
            
            callback.finding_id = finding_id
            callback.correlated = True
            logger.info(f"OOB callback {callback_id} correlated with finding {finding_id}")

    def get_campaign_summary(self, campaign_id: str) -> Dict[str, Any]:
        """
        Retrieves campaign summary statistics.

        Args:
            campaign_id: Campaign UUID

        Returns:
            dict: Campaign summary with counts and status

        Raises:
            EvidenceStoreError: If campaign not found
        """
        with self.get_session() as session:
            campaign = session.query(Campaign).filter_by(campaign_id=campaign_id).first()
            if not campaign:
                raise EvidenceStoreError(f"Campaign not found: {campaign_id}")
            
            return {
                "campaign_id": campaign.campaign_id,
                "target_url": campaign.target_url,
                "target_type": campaign.target_type,
                "status": campaign.status,
                "started_at": campaign.started_at.isoformat(),
                "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
                "findings_count": campaign.findings_count,
                "critical_count": campaign.critical_count,
                "high_count": campaign.high_count,
                "sessions_count": len(campaign.sessions),
            }


logger.info("Evidence store module loaded")
