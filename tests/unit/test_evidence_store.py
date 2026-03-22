"""
Unit tests for evidence/store.py

Tests encrypted evidence storage with SQLCipher.
"""

import pytest
from python.evidence.store import EvidenceStore
from python.evidence.models import Campaign, Finding


@pytest.mark.unit
class TestEvidenceStore:
    """Test suite for EvidenceStore class."""
    
    @pytest.fixture
    def store(self, temp_dir):
        """Create an EvidenceStore instance with temp database."""
        db_path = temp_dir / "test_evidence.db"
        return EvidenceStore(str(db_path))
    
    def test_init_creates_database(self, temp_dir):
        """Test initialization creates database file."""
        db_path = temp_dir / "test.db"
        store = EvidenceStore(str(db_path))
        
        assert db_path.exists()
        store.close()
    
    def test_create_campaign(self, store):
        """Test creating a campaign."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com",
            profile="chatbot"
        )
        
        assert campaign.id is not None
        assert campaign.name == "Test Campaign"
        assert campaign.target_url == "https://example.com"
        assert campaign.status == "created"
    
    def test_get_campaign(self, store):
        """Test retrieving a campaign by ID."""
        created = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        retrieved = store.get_campaign(created.id)
        
        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.name == created.name
    
    def test_get_nonexistent_campaign(self, store):
        """Test retrieving nonexistent campaign returns None."""
        campaign = store.get_campaign("nonexistent_id")
        
        assert campaign is None
    
    def test_update_campaign_status(self, store):
        """Test updating campaign status."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        store.update_campaign_status(campaign.id, "running")
        updated = store.get_campaign(campaign.id)
        
        assert updated.status == "running"
    
    def test_add_finding(self, store, sample_finding):
        """Test adding a finding to a campaign."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        finding = store.add_finding(
            campaign_id=campaign.id,
            finding_type=sample_finding["finding_type"],
            severity=sample_finding["severity"],
            payload=sample_finding["payload"],
            response=sample_finding["response"],
            cvss_score=sample_finding["cvss_score"]
        )
        
        assert finding.id is not None
        assert finding.campaign_id == campaign.id
        assert finding.finding_type == "prompt_injection"
    
    def test_get_findings_by_campaign(self, store, sample_finding):
        """Test retrieving all findings for a campaign."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        # Add multiple findings
        for i in range(3):
            store.add_finding(
                campaign_id=campaign.id,
                finding_type=sample_finding["finding_type"],
                severity=sample_finding["severity"],
                payload=f"payload_{i}",
                response=f"response_{i}",
                cvss_score=7.5
            )
        
        findings = store.get_findings_by_campaign(campaign.id)
        
        assert len(findings) == 3
        assert all(f.campaign_id == campaign.id for f in findings)
    
    def test_get_findings_by_severity(self, store):
        """Test retrieving findings filtered by severity."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        # Add findings with different severities
        store.add_finding(
            campaign_id=campaign.id,
            finding_type="prompt_injection",
            severity="critical",
            payload="test1",
            response="response1"
        )
        store.add_finding(
            campaign_id=campaign.id,
            finding_type="prompt_injection",
            severity="high",
            payload="test2",
            response="response2"
        )
        
        critical_findings = store.get_findings_by_severity(campaign.id, "critical")
        
        assert len(critical_findings) == 1
        assert critical_findings[0].severity == "critical"
    
    def test_mark_finding_verified(self, store, sample_finding):
        """Test marking a finding as verified."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        finding = store.add_finding(
            campaign_id=campaign.id,
            finding_type=sample_finding["finding_type"],
            severity=sample_finding["severity"],
            payload=sample_finding["payload"],
            response=sample_finding["response"]
        )
        
        store.mark_finding_verified(finding.id, verified=True)
        updated = store.get_finding(finding.id)
        
        assert updated.verified is True
    
    def test_mark_finding_false_positive(self, store, sample_finding):
        """Test marking a finding as false positive."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        finding = store.add_finding(
            campaign_id=campaign.id,
            finding_type=sample_finding["finding_type"],
            severity=sample_finding["severity"],
            payload=sample_finding["payload"],
            response=sample_finding["response"]
        )
        
        store.mark_finding_false_positive(finding.id, is_fp=True)
        updated = store.get_finding(finding.id)
        
        assert updated.false_positive is True
    
    def test_get_campaign_statistics(self, store):
        """Test retrieving campaign statistics."""
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        # Add findings with different severities
        severities = ["critical", "high", "high", "medium", "low"]
        for severity in severities:
            store.add_finding(
                campaign_id=campaign.id,
                finding_type="test",
                severity=severity,
                payload="test",
                response="test"
            )
        
        stats = store.get_campaign_statistics(campaign.id)
        
        assert stats["total_findings"] == 5
        assert stats["critical"] == 1
        assert stats["high"] == 2
        assert stats["medium"] == 1
        assert stats["low"] == 1
    
    def test_thread_safety(self, store):
        """Test that store operations are thread-safe."""
        import threading
        
        campaign = store.create_campaign(
            name="Test Campaign",
            target_url="https://example.com"
        )
        
        def add_findings():
            for i in range(10):
                store.add_finding(
                    campaign_id=campaign.id,
                    finding_type="test",
                    severity="high",
                    payload=f"payload_{i}",
                    response=f"response_{i}"
                )
        
        threads = [threading.Thread(target=add_findings) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        findings = store.get_findings_by_campaign(campaign.id)
        assert len(findings) == 30
    
    def test_close(self, store):
        """Test closing the store."""
        store.close()
        
        # Should not be able to perform operations after close
        with pytest.raises(Exception):
            store.create_campaign("Test", "https://example.com")
