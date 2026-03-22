"""
Session manager for maintaining authentication state across probes.

Handles session lifecycle, token refresh, and authentication context
for multi-turn conversations and long-running campaigns.
"""

import logging
import time
from typing import Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class Session:
    """
    Represents an authenticated session.
    
    Attributes:
        session_id: Unique session identifier
        auth: Authentication context
        created_at: Session creation timestamp
        last_used: Last activity timestamp
        expires_at: Session expiration timestamp
        metadata: Additional session metadata
    """
    
    def __init__(
        self,
        session_id: str,
        auth: Dict[str, str],
        ttl_seconds: int = 3600
    ):
        """
        Initialize a new session.
        
        Args:
            session_id: Unique session identifier
            auth: Authentication context
            ttl_seconds: Time-to-live in seconds (default 1 hour)
        """
        self.session_id = session_id
        self.auth = auth
        self.created_at = datetime.now()
        self.last_used = datetime.now()
        self.expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
        self.metadata: Dict[str, str] = {}
        
        logger.info(f"Session created: {session_id}, expires at {self.expires_at}")
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now() >= self.expires_at
    
    def is_valid(self) -> bool:
        """Check if session is valid (not expired)."""
        return not self.is_expired()
    
    def touch(self):
        """Update last_used timestamp."""
        self.last_used = datetime.now()
    
    def extend(self, seconds: int):
        """
        Extend session expiration.
        
        Args:
            seconds: Number of seconds to extend
        """
        self.expires_at = datetime.now() + timedelta(seconds=seconds)
        logger.info(f"Session {self.session_id} extended to {self.expires_at}")
    
    def update_auth(self, auth: Dict[str, str]):
        """
        Update authentication context.
        
        Args:
            auth: New authentication context
        """
        self.auth = auth
        self.touch()
        logger.info(f"Session {self.session_id} auth updated")


class SessionManager:
    """
    Manages multiple sessions for different targets/campaigns.
    
    Handles session creation, retrieval, refresh, and cleanup.
    """
    
    def __init__(self):
        """Initialize session manager."""
        self.sessions: Dict[str, Session] = {}
        self.default_ttl = 3600  # 1 hour
        logger.info("SessionManager initialized")
    
    def create_session(
        self,
        session_id: str,
        auth: Dict[str, str],
        ttl_seconds: Optional[int] = None
    ) -> Session:
        """
        Create a new session.
        
        Args:
            session_id: Unique session identifier
            auth: Authentication context
            ttl_seconds: Time-to-live in seconds (uses default if None)
            
        Returns:
            Session: Created session
        """
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl
        
        session = Session(session_id, auth, ttl_seconds)
        self.sessions[session_id] = session
        
        logger.info(f"Session created: {session_id}")
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve a session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session: Session if found and valid, None otherwise
        """
        session = self.sessions.get(session_id)
        
        if session is None:
            logger.warning(f"Session not found: {session_id}")
            return None
        
        if session.is_expired():
            logger.warning(f"Session expired: {session_id}")
            self.delete_session(session_id)
            return None
        
        session.touch()
        return session
    
    def delete_session(self, session_id: str):
        """
        Delete a session.
        
        Args:
            session_id: Session identifier
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            logger.info(f"Session deleted: {session_id}")
    
    def cleanup_expired(self):
        """Remove all expired sessions."""
        expired = [
            sid for sid, session in self.sessions.items()
            if session.is_expired()
        ]
        
        for session_id in expired:
            self.delete_session(session_id)
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")
    
    def get_auth(self, session_id: str) -> Optional[Dict[str, str]]:
        """
        Get authentication context for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Dict: Authentication context, or None if session not found
        """
        session = self.get_session(session_id)
        return session.auth if session else None
    
    def update_auth(self, session_id: str, auth: Dict[str, str]) -> bool:
        """
        Update authentication context for a session.
        
        Args:
            session_id: Session identifier
            auth: New authentication context
            
        Returns:
            bool: True if updated, False if session not found
        """
        session = self.get_session(session_id)
        if session:
            session.update_auth(auth)
            return True
        return False
    
    def extend_session(self, session_id: str, seconds: int) -> bool:
        """
        Extend session expiration.
        
        Args:
            session_id: Session identifier
            seconds: Number of seconds to extend
            
        Returns:
            bool: True if extended, False if session not found
        """
        session = self.get_session(session_id)
        if session:
            session.extend(seconds)
            return True
        return False
    
    def list_sessions(self) -> Dict[str, Dict]:
        """
        List all active sessions.
        
        Returns:
            Dict: Map of session_id to session info
        """
        self.cleanup_expired()
        
        return {
            sid: {
                "created_at": session.created_at.isoformat(),
                "last_used": session.last_used.isoformat(),
                "expires_at": session.expires_at.isoformat(),
                "is_valid": session.is_valid()
            }
            for sid, session in self.sessions.items()
        }
    
    def get_or_create_session(
        self,
        session_id: str,
        auth: Dict[str, str],
        ttl_seconds: Optional[int] = None
    ) -> Session:
        """
        Get existing session or create new one.
        
        Args:
            session_id: Session identifier
            auth: Authentication context (used if creating new)
            ttl_seconds: Time-to-live in seconds
            
        Returns:
            Session: Existing or newly created session
        """
        session = self.get_session(session_id)
        if session:
            return session
        
        return self.create_session(session_id, auth, ttl_seconds)


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """
    Get global session manager instance.
    
    Returns:
        SessionManager: Global session manager
    """
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
