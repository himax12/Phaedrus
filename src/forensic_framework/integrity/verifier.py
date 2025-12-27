"""
Integrity Verifier - High-level API for evidence verification.

Provides easy-to-use methods for:
- Verifying individual logs against the chain
- Generating verification reports
- Detecting tampering
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .logchain import LogChain, EvidenceBlock
from .merkle_tree import MerkleTree, MerkleProof


@dataclass
class VerificationResult:
    """Result of an integrity verification."""

    is_valid: bool
    message: str
    timestamp: datetime
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_valid": self.is_valid,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


class IntegrityVerifier:
    """
    High-level API for evidence integrity verification.

    Provides methods to:
    - Verify the entire chain
    - Verify specific blocks
    - Verify individual logs
    - Generate verification reports
    """

    def __init__(self, chain: LogChain):
        """
        Initialize verifier.

        Args:
            chain: LogChain to verify against
        """
        self.chain = chain

    def verify_chain(self) -> VerificationResult:
        """
        Verify the entire chain integrity.

        Returns:
            VerificationResult with chain status
        """
        is_valid, errors = self.chain.verify_chain()

        return VerificationResult(
            is_valid=is_valid,
            message="Chain integrity verified" if is_valid else "Chain integrity compromised",
            timestamp=datetime.utcnow(),
            details={
                "block_count": self.chain.length,
                "errors": errors,
                "latest_block_hash": (
                    self.chain.latest_block.block_hash if self.chain.latest_block else None
                ),
            },
        )

    def verify_block(self, block_id: int) -> VerificationResult:
        """
        Verify a specific block.

        Args:
            block_id: ID of the block to verify

        Returns:
            VerificationResult with block status
        """
        block = self.chain.get_block(block_id)

        if block is None:
            return VerificationResult(
                is_valid=False,
                message=f"Block {block_id} not found",
                timestamp=datetime.utcnow(),
                details={"block_id": block_id},
            )

        # Verify block hash
        computed_hash = block.compute_hash()
        hash_valid = block.block_hash == computed_hash

        # Verify chain link
        chain_valid = True
        if block_id > 0:
            prev_block = self.chain.get_block(block_id - 1)
            if prev_block:
                chain_valid = block.prev_block_hash == prev_block.block_hash

        is_valid = hash_valid and chain_valid

        return VerificationResult(
            is_valid=is_valid,
            message="Block verified" if is_valid else "Block verification failed",
            timestamp=datetime.utcnow(),
            details={
                "block_id": block_id,
                "merkle_root": block.merkle_root,
                "block_hash": block.block_hash,
                "computed_hash": computed_hash,
                "hash_valid": hash_valid,
                "chain_valid": chain_valid,
                "log_count": block.log_count,
                "block_timestamp": block.timestamp.isoformat(),
            },
        )

    def verify_log_exists(
        self,
        log_id: str,
        log_content: str,
    ) -> VerificationResult:
        """
        Verify a log exists in the chain.

        Args:
            log_id: ID of the log
            log_content: Content to verify

        Returns:
            VerificationResult with verification status
        """
        is_valid, message = self.chain.verify_log(log_id, log_content)

        return VerificationResult(
            is_valid=is_valid,
            message=message,
            timestamp=datetime.utcnow(),
            details={
                "log_id": log_id,
                "content_preview": log_content[:100] + "..." if len(log_content) > 100 else log_content,
            },
        )

    def generate_verification_report(self) -> dict[str, Any]:
        """
        Generate a comprehensive verification report.

        Returns:
            Dict with full chain verification details
        """
        chain_result = self.verify_chain()

        block_verifications = []
        for i in range(self.chain.length):
            block_result = self.verify_block(i)
            block_verifications.append(block_result.to_dict())

        return {
            "report_timestamp": datetime.utcnow().isoformat(),
            "chain_verification": chain_result.to_dict(),
            "block_count": self.chain.length,
            "block_verifications": block_verifications,
            "anchoring_data": self.chain.export_for_anchoring(),
            "summary": {
                "all_blocks_valid": all(
                    bv["is_valid"] for bv in block_verifications
                ),
                "chain_intact": chain_result.is_valid,
            },
        }

    def detect_tampering(
        self,
        logs: list[tuple[str, str]],  # List of (log_id, content)
    ) -> list[dict[str, Any]]:
        """
        Detect potential tampering in a set of logs.

        Args:
            logs: List of (log_id, content) tuples to verify

        Returns:
            List of tampering detection results
        """
        results = []

        for log_id, content in logs:
            result = self.verify_log_exists(log_id, content)
            results.append({
                "log_id": log_id,
                "verified": result.is_valid,
                "message": result.message,
                "potential_tampering": not result.is_valid,
            })

        return results


def main():
    """Demo IntegrityVerifier functionality."""
    print("Integrity Verifier Demo\n")

    # Create chain with some blocks
    chain = LogChain()

    # Add and seal some blocks
    for i in range(3):
        for j in range(5):
            chain.add_log(f"log-{i}-{j}", f"Block {i} Log {j} content")
        chain.seal_block(force=True)

    # Create verifier
    verifier = IntegrityVerifier(chain)

    # Verify chain
    print("Chain Verification:")
    result = verifier.verify_chain()
    print(f"  Valid: {result.is_valid}")
    print(f"  Message: {result.message}")
    print(f"  Blocks: {result.details['block_count']}")

    # Verify specific block
    print("\nBlock 1 Verification:")
    result = verifier.verify_block(1)
    print(f"  Valid: {result.is_valid}")
    print(f"  Merkle Root: {result.details['merkle_root'][:32]}...")

    # Generate report
    print("\nGenerating verification report...")
    report = verifier.generate_verification_report()
    print(f"  Report timestamp: {report['report_timestamp']}")
    print(f"  Chain intact: {report['summary']['chain_intact']}")
    print(f"  All blocks valid: {report['summary']['all_blocks_valid']}")


if __name__ == "__main__":
    main()
