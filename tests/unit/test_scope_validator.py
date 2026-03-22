"""
Unit tests for scope_validator.py

Tests the scope validation logic that prevents out-of-scope testing.
"""

import pytest
from python.core.scope_validator import ScopeValidator, OutOfScopeError


@pytest.mark.unit
class TestScopeValidator:
    """Test suite for ScopeValidator class."""
    
    def test_init_with_valid_scope_file(self, test_scope_file):
        """Test initialization with valid scope file."""
        validator = ScopeValidator(str(test_scope_file))
        
        assert validator.allowed_domains == ["example.com", "test.com"]
        assert validator.excluded_paths == ["/admin", "/internal"]
        assert validator.excluded_extensions == [".jpg", ".png"]
    
    def test_init_with_missing_scope_file(self, temp_dir):
        """Test initialization with missing scope file raises error."""
        missing_file = temp_dir / "missing.yaml"
        
        with pytest.raises(FileNotFoundError) as exc_info:
            ScopeValidator(str(missing_file))
        
        assert "scope.yaml not found" in str(exc_info.value)
    
    def test_is_in_scope_allowed_domain(self, test_scope_file):
        """Test URL with allowed domain is in scope."""
        validator = ScopeValidator(str(test_scope_file))
        
        assert validator.is_in_scope("https://example.com/api/chat")
        assert validator.is_in_scope("https://test.com/endpoint")
    
    def test_is_in_scope_disallowed_domain(self, test_scope_file):
        """Test URL with disallowed domain is out of scope."""
        validator = ScopeValidator(str(test_scope_file))
        
        assert not validator.is_in_scope("https://evil.com/api")
        assert not validator.is_in_scope("https://other.com/endpoint")
    
    def test_is_in_scope_excluded_path(self, test_scope_file):
        """Test URL with excluded path is out of scope."""
        validator = ScopeValidator(str(test_scope_file))
        
        assert not validator.is_in_scope("https://example.com/admin/users")
        assert not validator.is_in_scope("https://example.com/internal/config")
    
    def test_is_in_scope_excluded_extension(self, test_scope_file):
        """Test URL with excluded extension is out of scope."""
        validator = ScopeValidator(str(test_scope_file))
        
        assert not validator.is_in_scope("https://example.com/image.jpg")
        assert not validator.is_in_scope("https://example.com/photo.png")
    
    def test_validate_or_raise_in_scope(self, test_scope_file):
        """Test validate_or_raise with in-scope URL does not raise."""
        validator = ScopeValidator(str(test_scope_file))
        
        # Should not raise
        validator.validate_or_raise("https://example.com/api/chat")
    
    def test_validate_or_raise_out_of_scope(self, test_scope_file):
        """Test validate_or_raise with out-of-scope URL raises error."""
        validator = ScopeValidator(str(test_scope_file))
        
        with pytest.raises(OutOfScopeError) as exc_info:
            validator.validate_or_raise("https://evil.com/api")
        
        assert "OUT OF SCOPE" in str(exc_info.value)
        assert "evil.com" in str(exc_info.value)
    
    def test_validate_or_raise_excluded_path(self, test_scope_file):
        """Test validate_or_raise with excluded path raises error."""
        validator = ScopeValidator(str(test_scope_file))
        
        with pytest.raises(OutOfScopeError):
            validator.validate_or_raise("https://example.com/admin/users")
    
    def test_subdomain_handling(self, test_scope_file):
        """Test that subdomains are not automatically allowed."""
        validator = ScopeValidator(str(test_scope_file))
        
        # Subdomain should not be allowed unless explicitly listed
        assert not validator.is_in_scope("https://api.example.com/endpoint")
        assert not validator.is_in_scope("https://sub.test.com/api")
    
    def test_path_prefix_matching(self, test_scope_file):
        """Test that excluded paths match by prefix."""
        validator = ScopeValidator(str(test_scope_file))
        
        # /admin should match /admin/anything
        assert not validator.is_in_scope("https://example.com/admin/users/123")
        assert not validator.is_in_scope("https://example.com/internal/secrets")
        
        # But not partial matches
        assert validator.is_in_scope("https://example.com/administrator")
