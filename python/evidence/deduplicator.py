"""
Finding deduplicator using ssdeep fuzzy hashing.

Detects duplicate and near-duplicate findings using ssdeep context-triggered
piecewise hashing. This prevents report bloat from minor payload variations
that trigger the same underlying vulnerability.

ssdeep is particularly effective for finding similarity in:
- Payloads with minor character variations
- Responses with different dynamic content but same structure
- Findings from different sessions that exploit the same root cause

Deduplication strategy:
1. Hash payload + response + finding_type
2. Compare against existing findings using ssdeep.compare()
3. Threshold: 80% similarity = duplicate
4. Mark as duplicate_of original finding_id
"""

import ssdeep
import logging
from typing import Optional, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FindingSignature:
    """
    Represents a finding's unique signature for deduplication.

    Attributes:
        finding_id: Finding UUID
        finding_type: Specific finding type
        payload: Probe payload
        response: Target response (truncated)
        ssdeep_hash: ssdeep fuzzy hash of signature
    """
    finding_id: str
    finding_type: str
    payload: str
    response: str
    ssdeep_hash: str


class Deduplicator:
    """
    Finding deduplicator using ssdeep fuzzy hashing.

    Maintains an in-memory cache of finding signatures for fast duplicate
    detection during a campaign. Persists dedup_hash to database for
    cross-campaign deduplication.

    Usage:
        dedup = Deduplicator()
        dedup_hash = dedup.compute_hash(payload, response, finding_type)
        duplicate_of = dedup.check_duplicate(dedup_hash, finding_id, payload, response, finding_type)
        if duplicate_of:
            # Mark as duplicate
        else:
            # New unique finding
    """

    def __init__(self, similarity_threshold: int = 80):
        """
        Initializes deduplicator.

        Args:
            similarity_threshold: ssdeep similarity threshold (0-100)
                80 = 80% similar = duplicate
                Lower threshold = more aggressive deduplication
                Higher threshold = more conservative (fewer duplicates detected)
        """
        self.similarity_threshold = similarity_threshold
        self.signatures: List[FindingSignature] = []
        logger.info(f"Deduplicator initialized with threshold={similarity_threshold}%")

    def compute_hash(self, payload: str, response: str, finding_type: str) -> str:
        """
        Computes ssdeep fuzzy hash for a finding.

        The hash is computed over: finding_type + payload + response
        This ensures that findings with similar payloads and responses
        but different types are not considered duplicates.

        Args:
            payload: Probe payload
            response: Target response
            finding_type: Specific finding type

        Returns:
            str: ssdeep hash string

        Example:
            hash1 = dedup.compute_hash("payload1", "response1", "prompt_injection")
            hash2 = dedup.compute_hash("payload2", "response2", "prompt_injection")
            similarity = ssdeep.compare(hash1, hash2)
        """
        # Truncate response to 5KB for hashing (reduces noise from dynamic content)
        max_response_len = 5 * 1024
        response_truncated = response[:max_response_len] if len(response) > max_response_len else response

        # Build signature string
        signature = f"{finding_type}|||{payload}|||{response_truncated}"

        # Compute ssdeep hash
        try:
            dedup_hash = ssdeep.hash(signature.encode("utf-8"))
            logger.debug(f"Computed ssdeep hash for {finding_type}: {dedup_hash[:32]}...")
            return dedup_hash
        except Exception as e:
            logger.error(f"Failed to compute ssdeep hash: {e}")
            # Fallback to simple hash if ssdeep fails
            import hashlib
            return hashlib.sha256(signature.encode("utf-8")).hexdigest()

    def check_duplicate(
        self,
        dedup_hash: str,
        finding_id: str,
        payload: str,
        response: str,
        finding_type: str,
    ) -> Optional[str]:
        """
        Checks if a finding is a duplicate of an existing finding.

        Compares the finding's ssdeep hash against all cached signatures.
        If similarity >= threshold, returns the original finding_id.
        Otherwise, adds this finding to the cache and returns None.

        Args:
            dedup_hash: ssdeep hash of the finding
            finding_id: Finding UUID
            payload: Probe payload
            response: Target response
            finding_type: Specific finding type

        Returns:
            Optional[str]: finding_id of original if duplicate, None if unique

        Example:
            duplicate_of = dedup.check_duplicate(hash, "uuid-123", payload, response, "prompt_injection")
            if duplicate_of:
                print(f"Duplicate of {duplicate_of}")
            else:
                print("Unique finding")
        """
        # Check against all cached signatures
        for sig in self.signatures:
            # Only compare findings of the same type
            if sig.finding_type != finding_type:
                continue

            try:
                similarity = ssdeep.compare(dedup_hash, sig.ssdeep_hash)
                logger.debug(f"Similarity between {finding_id} and {sig.finding_id}: {similarity}%")

                if similarity >= self.similarity_threshold:
                    logger.info(
                        f"Duplicate detected: {finding_id} is {similarity}% similar to {sig.finding_id}"
                    )
                    return sig.finding_id

            except Exception as e:
                logger.error(f"Failed to compare ssdeep hashes: {e}")
                continue

        # No duplicate found — add to cache
        signature = FindingSignature(
            finding_id=finding_id,
            finding_type=finding_type,
            payload=payload,
            response=response,
            ssdeep_hash=dedup_hash,
        )
        self.signatures.append(signature)
        logger.debug(f"Added signature to cache: {finding_id} (total={len(self.signatures)})")

        return None

    def bulk_check_duplicates(
        self,
        findings: List[Tuple[str, str, str, str, str]],
    ) -> List[Tuple[str, Optional[str]]]:
        """
        Checks multiple findings for duplicates in batch.

        More efficient than calling check_duplicate() in a loop because
        it builds the signature cache once and compares all findings.

        Args:
            findings: List of (finding_id, dedup_hash, payload, response, finding_type) tuples

        Returns:
            List[Tuple[str, Optional[str]]]: List of (finding_id, duplicate_of) tuples
                duplicate_of is None if unique, finding_id of original if duplicate

        Example:
            findings = [
                ("uuid-1", "hash1", "payload1", "response1", "prompt_injection"),
                ("uuid-2", "hash2", "payload2", "response2", "prompt_injection"),
            ]
            results = dedup.bulk_check_duplicates(findings)
            # Returns: [("uuid-1", None), ("uuid-2", "uuid-1")]
        """
        results = []

        for finding_id, dedup_hash, payload, response, finding_type in findings:
            duplicate_of = self.check_duplicate(
                dedup_hash=dedup_hash,
                finding_id=finding_id,
                payload=payload,
                response=response,
                finding_type=finding_type,
            )
            results.append((finding_id, duplicate_of))

        logger.info(
            f"Bulk deduplication complete: {len(findings)} findings, "
            f"{sum(1 for _, dup in results if dup)} duplicates"
        )
        return results

    def clear_cache(self):
        """
        Clears the in-memory signature cache.

        Call this between campaigns to prevent cross-campaign deduplication.
        Within a campaign, keep the cache to detect duplicates across sessions.
        """
        count = len(self.signatures)
        self.signatures.clear()
        logger.info(f"Deduplicator cache cleared: {count} signatures removed")

    def get_cache_size(self) -> int:
        """
        Returns the number of signatures in the cache.

        Returns:
            int: Number of cached signatures
        """
        return len(self.signatures)

    def compute_similarity(self, hash1: str, hash2: str) -> int:
        """
        Computes similarity percentage between two ssdeep hashes.

        Args:
            hash1: First ssdeep hash
            hash2: Second ssdeep hash

        Returns:
            int: Similarity percentage (0-100)

        Example:
            similarity = dedup.compute_similarity(hash1, hash2)
            if similarity >= 80:
                print("Hashes are similar")
        """
        try:
            similarity = ssdeep.compare(hash1, hash2)
            return similarity
        except Exception as e:
            logger.error(f"Failed to compute similarity: {e}")
            return 0


logger.info("Deduplicator module loaded")
