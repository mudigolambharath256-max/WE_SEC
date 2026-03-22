"""
Local CVE database cache with NVD API integration.

Maintains a local SQLite cache of CVE data to reduce API calls and improve
performance. Automatically refreshes stale entries and handles rate limiting.

NVD API rate limits:
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds

Cache strategy:
- CVEs older than 30 days: refresh every 7 days
- CVEs newer than 30 days: refresh every 24 hours
- Cache hits avoid API calls entirely

Data stored:
- CVE ID, description, CVSS scores, CWE, references
- Published date, last modified date
- Exploit availability (from references)
- CISA KEV status
"""

import os
import sqlite3
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import json
import time

try:
    import nvdlib
except ImportError:
    nvdlib = None
    logging.warning("nvdlib not installed, CVE cache will be limited")

logger = logging.getLogger(__name__)


class CVECache:
    """
    Local CVE database cache with NVD API integration.

    Provides fast CVE lookups with automatic cache management and
    rate-limited NVD API fallback.

    Args:
        cache_path: Path to SQLite cache database
        api_key: NVD API key (optional, increases rate limit)

    Usage:
        cache = CVECache()
        cve_data = cache.get_cve("CVE-2024-1234")
        if cve_data:
            print(f"CVSS: {cve_data['cvss_score']}")
    """

    def __init__(self, cache_path: str = "./output/cve_cache.db", api_key: Optional[str] = None):
        self.cache_path = Path(cache_path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        
        # Rate limiting
        self.last_api_call = 0
        self.api_delay = 6.0 if not self.api_key else 0.6  # seconds between calls
        
        # Initialize database
        self._init_db()
        logger.info(f"CVE cache initialized: {self.cache_path}")

    def _init_db(self):
        """Creates CVE cache database schema."""
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                cvss_v2_score REAL,
                cvss_v2_vector TEXT,
                cwe_id TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                references TEXT,
                exploit_available INTEGER DEFAULT 0,
                kev_listed INTEGER DEFAULT 0,
                cached_at TEXT,
                last_refreshed TEXT
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_cache(cve_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cached_at ON cve_cache(cached_at)
        """)
        
        conn.commit()
        conn.close()
        logger.debug("CVE cache schema initialized")

    def get_cve(self, cve_id: str, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
        """
        Retrieves CVE data from cache or NVD API.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
            force_refresh: Force API refresh even if cached

        Returns:
            Optional[Dict[str, Any]]: CVE data dictionary or None if not found

        Example:
            cve = cache.get_cve("CVE-2024-1234")
            if cve:
                print(f"{cve['cve_id']}: CVSS {cve['cvss_v3_score']}")
        """
        # Normalize CVE ID
        cve_id = cve_id.upper().strip()
        
        # Check cache first
        if not force_refresh:
            cached = self._get_from_cache(cve_id)
            if cached and not self._is_stale(cached):
                logger.debug(f"CVE cache hit: {cve_id}")
                return cached

        # Cache miss or stale — fetch from NVD API
        logger.debug(f"CVE cache miss: {cve_id}, fetching from NVD")
        cve_data = self._fetch_from_nvd(cve_id)
        
        if cve_data:
            self._store_in_cache(cve_data)
            return cve_data
        
        return None

    def _get_from_cache(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves CVE from local cache."""
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT cve_id, description, cvss_v3_score, cvss_v3_vector,
                   cvss_v2_score, cvss_v2_vector, cwe_id, published_date,
                   last_modified_date, references, exploit_available,
                   kev_listed, cached_at, last_refreshed
            FROM cve_cache
            WHERE cve_id = ?
        """, (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            "cve_id": row[0],
            "description": row[1],
            "cvss_v3_score": row[2],
            "cvss_v3_vector": row[3],
            "cvss_v2_score": row[4],
            "cvss_v2_vector": row[5],
            "cwe_id": row[6],
            "published_date": row[7],
            "last_modified_date": row[8],
            "references": json.loads(row[9]) if row[9] else [],
            "exploit_available": bool(row[10]),
            "kev_listed": bool(row[11]),
            "cached_at": row[12],
            "last_refreshed": row[13],
        }

    def _is_stale(self, cve_data: Dict[str, Any]) -> bool:
        """Checks if cached CVE data is stale and needs refresh."""
        last_refreshed = datetime.fromisoformat(cve_data["last_refreshed"])
        age = datetime.utcnow() - last_refreshed
        
        # CVEs older than 30 days: refresh every 7 days
        published = datetime.fromisoformat(cve_data["published_date"])
        cve_age = datetime.utcnow() - published
        
        if cve_age > timedelta(days=30):
            return age > timedelta(days=7)
        else:
            # Recent CVEs: refresh every 24 hours
            return age > timedelta(hours=24)

    def _fetch_from_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetches CVE data from NVD API with rate limiting."""
        if not nvdlib:
            logger.error("nvdlib not installed, cannot fetch from NVD")
            return None
        
        # Rate limiting
        elapsed = time.time() - self.last_api_call
        if elapsed < self.api_delay:
            sleep_time = self.api_delay - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        try:
            # Fetch from NVD
            self.last_api_call = time.time()
            cve = nvdlib.searchCVE(cveId=cve_id, key=self.api_key)[0]
            
            # Extract data
            cve_data = {
                "cve_id": cve_id,
                "description": cve.descriptions[0].value if cve.descriptions else "No description",
                "cvss_v3_score": None,
                "cvss_v3_vector": None,
                "cvss_v2_score": None,
                "cvss_v2_vector": None,
                "cwe_id": None,
                "published_date": cve.published.isoformat() if cve.published else None,
                "last_modified_date": cve.lastModified.isoformat() if cve.lastModified else None,
                "references": [],
                "exploit_available": False,
                "kev_listed": False,
            }
            
            # Extract CVSS scores
            if hasattr(cve, 'v31score') and cve.v31score:
                cve_data["cvss_v3_score"] = cve.v31score
                cve_data["cvss_v3_vector"] = cve.v31vector if hasattr(cve, 'v31vector') else None
            elif hasattr(cve, 'v3score') and cve.v3score:
                cve_data["cvss_v3_score"] = cve.v3score
                cve_data["cvss_v3_vector"] = cve.v3vector if hasattr(cve, 'v3vector') else None
            
            if hasattr(cve, 'v2score') and cve.v2score:
                cve_data["cvss_v2_score"] = cve.v2score
                cve_data["cvss_v2_vector"] = cve.v2vector if hasattr(cve, 'v2vector') else None
            
            # Extract CWE
            if hasattr(cve, 'cwe') and cve.cwe:
                cve_data["cwe_id"] = cve.cwe
            
            # Extract references and check for exploits
            if hasattr(cve, 'references') and cve.references:
                for ref in cve.references:
                    ref_url = ref.url if hasattr(ref, 'url') else str(ref)
                    cve_data["references"].append(ref_url)
                    
                    # Check for exploit indicators in references
                    exploit_keywords = ["exploit", "poc", "proof-of-concept", "metasploit", "exploit-db"]
                    if any(keyword in ref_url.lower() for keyword in exploit_keywords):
                        cve_data["exploit_available"] = True
            
            logger.info(f"Fetched CVE from NVD: {cve_id} (CVSS: {cve_data['cvss_v3_score']})")
            return cve_data
            
        except Exception as e:
            logger.error(f"Failed to fetch CVE {cve_id} from NVD: {e}")
            return None

    def _store_in_cache(self, cve_data: Dict[str, Any]):
        """Stores CVE data in local cache."""
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()
        
        now = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT OR REPLACE INTO cve_cache (
                cve_id, description, cvss_v3_score, cvss_v3_vector,
                cvss_v2_score, cvss_v2_vector, cwe_id, published_date,
                last_modified_date, references, exploit_available,
                kev_listed, cached_at, last_refreshed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_data["cve_id"],
            cve_data["description"],
            cve_data["cvss_v3_score"],
            cve_data["cvss_v3_vector"],
            cve_data["cvss_v2_score"],
            cve_data["cvss_v2_vector"],
            cve_data["cwe_id"],
            cve_data["published_date"],
            cve_data["last_modified_date"],
            json.dumps(cve_data["references"]),
            int(cve_data["exploit_available"]),
            int(cve_data["kev_listed"]),
            now,
            now,
        ))
        
        conn.commit()
        conn.close()
        logger.debug(f"Stored CVE in cache: {cve_data['cve_id']}")

    def bulk_get_cves(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Retrieves multiple CVEs in batch.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary mapping CVE ID to CVE data

        Example:
            cves = cache.bulk_get_cves(["CVE-2024-1234", "CVE-2024-5678"])
            for cve_id, cve_data in cves.items():
                print(f"{cve_id}: {cve_data['cvss_v3_score']}")
        """
        results = {}
        for cve_id in cve_ids:
            cve_data = self.get_cve(cve_id)
            if cve_data:
                results[cve_id] = cve_data
        
        logger.info(f"Bulk CVE lookup: {len(results)}/{len(cve_ids)} found")
        return results

    def mark_kev(self, cve_id: str):
        """
        Marks a CVE as listed in CISA KEV catalog.

        Args:
            cve_id: CVE identifier
        """
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE cve_cache
            SET kev_listed = 1
            WHERE cve_id = ?
        """, (cve_id,))
        
        conn.commit()
        conn.close()
        logger.info(f"Marked CVE as KEV: {cve_id}")

    def get_cache_stats(self) -> Dict[str, int]:
        """
        Returns cache statistics.

        Returns:
            dict: Cache statistics (total_cves, with_exploits, kev_listed)
        """
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM cve_cache")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cve_cache WHERE exploit_available = 1")
        with_exploits = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cve_cache WHERE kev_listed = 1")
        kev_listed = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_cves": total,
            "with_exploits": with_exploits,
            "kev_listed": kev_listed,
        }


logger.info("CVE cache module loaded")
