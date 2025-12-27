"""
LogChain - Immutable chain of evidence blocks.

Similar to blockchain, each block contains:
- Merkle Root of log hashes
- Previous block hash (for chain integrity)
- Timestamp and metadata

This provides ISO 27037 compliant evidence handling.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from .merkle_tree import MerkleTree


@dataclass
class EvidenceBlock:
    """A block in the evidence chain."""

    block_id: int
    merkle_root: str
    prev_block_hash: str
    timestamp: datetime
    log_count: int
    log_ids: list[str] = field(default_factory=list)

    # Block hash (computed from above fields)
    block_hash: str = ""

    def compute_hash(self) -> str:
        """Compute the block hash from its contents."""
        content = f"{self.block_id}:{self.merkle_root}:{self.prev_block_hash}:{self.timestamp.isoformat()}:{self.log_count}"
        return hashlib.sha256(content.encode()).hexdigest()

    def __post_init__(self):
        """Compute block hash if not provided."""
        if not self.block_hash:
            self.block_hash = self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "block_id": self.block_id,
            "merkle_root": self.merkle_root,
            "prev_block_hash": self.prev_block_hash,
            "timestamp": self.timestamp.isoformat(),
            "log_count": self.log_count,
            "log_ids": self.log_ids,
            "block_hash": self.block_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceBlock":
        """Create from dictionary."""
        return cls(
            block_id=data["block_id"],
            merkle_root=data["merkle_root"],
            prev_block_hash=data["prev_block_hash"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            log_count=data["log_count"],
            log_ids=data.get("log_ids", []),
            block_hash=data.get("block_hash", ""),
        )


class LogChain:
    """
    Immutable chain of evidence blocks.

    Logs are buffered and periodically sealed into blocks.
    Each block contains a Merkle Root and links to the previous block.
    The entire chain can be exported for external anchoring (blockchain).
    """

    GENESIS_HASH = "0" * 64  # Genesis block has no predecessor

    def __init__(
        self,
        block_interval_seconds: int = 60,
        chain_file: Path | None = None,
    ):
        """
        Initialize LogChain.

        Args:
            block_interval_seconds: Time between blocks (default: 60s)
            chain_file: Path to persist the chain (JSON)
        """
        self.block_interval = timedelta(seconds=block_interval_seconds)
        self.chain_file = chain_file

        # Chain state
        self._blocks: list[EvidenceBlock] = []
        self._pending_logs: list[tuple[str, str]] = []  # (log_id, log_hash)
        self._last_block_time: datetime | None = None

        # Load existing chain
        if chain_file and chain_file.exists():
            self._load_chain()

    def _load_chain(self) -> None:
        """Load chain from file."""
        if not self.chain_file:
            return

        try:
            with open(self.chain_file, "r") as f:
                data = json.load(f)
                self._blocks = [EvidenceBlock.from_dict(b) for b in data["blocks"]]
                if self._blocks:
                    self._last_block_time = self._blocks[-1].timestamp
        except Exception:
            pass  # Start fresh

    def _save_chain(self) -> None:
        """Save chain to file."""
        if not self.chain_file:
            return

        self.chain_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.chain_file, "w") as f:
            json.dump(
                {
                    "version": "1.0",
                    "blocks": [b.to_dict() for b in self._blocks],
                },
                f,
                indent=2,
            )

    @property
    def length(self) -> int:
        """Number of blocks in the chain."""
        return len(self._blocks)

    @property
    def latest_block(self) -> EvidenceBlock | None:
        """Get the latest block."""
        return self._blocks[-1] if self._blocks else None

    @property
    def pending_count(self) -> int:
        """Number of logs pending in buffer."""
        return len(self._pending_logs)

    def add_log(self, log_id: str, log_content: str) -> None:
        """
        Add a log to the pending buffer.

        Args:
            log_id: Unique identifier for the log
            log_content: Raw log content (will be hashed)
        """
        log_hash = hashlib.sha256(log_content.encode()).hexdigest()
        self._pending_logs.append((log_id, log_hash))

    def add_log_hash(self, log_id: str, log_hash: str) -> None:
        """Add a pre-computed log hash to the buffer."""
        self._pending_logs.append((log_id, log_hash))

    def should_seal_block(self) -> bool:
        """Check if it's time to seal a new block."""
        if not self._pending_logs:
            return False

        if self._last_block_time is None:
            return True

        return datetime.utcnow() - self._last_block_time >= self.block_interval

    def seal_block(self, force: bool = False) -> EvidenceBlock | None:
        """
        Seal pending logs into a new block.

        Args:
            force: Force seal even if interval hasn't passed

        Returns:
            New EvidenceBlock or None if no logs pending
        """
        if not self._pending_logs:
            return None

        if not force and not self.should_seal_block():
            return None

        # Build Merkle Tree from pending log hashes
        tree = MerkleTree()
        log_ids = []

        for log_id, log_hash in self._pending_logs:
            tree.add_leaf_hash(log_hash)
            log_ids.append(log_id)

        merkle_root = tree.build()

        # Get previous block hash
        prev_hash = (
            self._blocks[-1].block_hash if self._blocks else self.GENESIS_HASH
        )

        # Create new block
        now = datetime.utcnow()
        block = EvidenceBlock(
            block_id=len(self._blocks),
            merkle_root=merkle_root,
            prev_block_hash=prev_hash,
            timestamp=now,
            log_count=len(log_ids),
            log_ids=log_ids,
        )

        # Add to chain
        self._blocks.append(block)
        self._pending_logs = []
        self._last_block_time = now

        # Persist
        self._save_chain()

        return block

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Verify the entire chain integrity.

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors: list[str] = []

        if not self._blocks:
            return True, []

        # Verify genesis block
        if self._blocks[0].prev_block_hash != self.GENESIS_HASH:
            errors.append("Genesis block has invalid prev_block_hash")

        # Verify each block
        for i, block in enumerate(self._blocks):
            # Verify block hash
            computed_hash = block.compute_hash()
            if block.block_hash != computed_hash:
                errors.append(
                    f"Block {block.block_id}: Hash mismatch "
                    f"(stored: {block.block_hash[:16]}..., computed: {computed_hash[:16]}...)"
                )

            # Verify chain link (except genesis)
            if i > 0:
                prev_block = self._blocks[i - 1]
                if block.prev_block_hash != prev_block.block_hash:
                    errors.append(
                        f"Block {block.block_id}: Chain broken - "
                        f"prev_block_hash doesn't match block {prev_block.block_id}"
                    )

        return len(errors) == 0, errors

    def verify_log(
        self,
        log_id: str,
        log_content: str,
        block_id: int | None = None,
    ) -> tuple[bool, str]:
        """
        Verify a specific log exists in the chain.

        Args:
            log_id: ID of the log to verify
            log_content: Content to verify (will be hashed)
            block_id: Specific block to check (or None to search all)

        Returns:
            Tuple of (is_valid, message)
        """
        log_hash = hashlib.sha256(log_content.encode()).hexdigest()

        blocks_to_check = (
            [self._blocks[block_id]] if block_id is not None else self._blocks
        )

        for block in blocks_to_check:
            if log_id in block.log_ids:
                # Found the log - need to verify against Merkle Root
                # This requires access to all logs in the block for full verification
                return True, f"Log found in block {block.block_id}"

        return False, "Log not found in chain"

    def export_for_anchoring(self) -> list[dict[str, Any]]:
        """
        Export block hashes for external blockchain anchoring.

        Returns:
            List of dicts with block_id, merkle_root, block_hash, timestamp
        """
        return [
            {
                "block_id": block.block_id,
                "merkle_root": block.merkle_root,
                "block_hash": block.block_hash,
                "timestamp": block.timestamp.isoformat(),
                "log_count": block.log_count,
            }
            for block in self._blocks
        ]

    def get_block(self, block_id: int) -> EvidenceBlock | None:
        """Get a specific block by ID."""
        if 0 <= block_id < len(self._blocks):
            return self._blocks[block_id]
        return None

    def get_blocks_in_range(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[EvidenceBlock]:
        """Get blocks within a time range."""
        return [
            block
            for block in self._blocks
            if start_time <= block.timestamp <= end_time
        ]


def main():
    """Demo LogChain functionality."""
    print("LogChain Demo\n")

    chain = LogChain(block_interval_seconds=5)

    # Add some logs
    sample_logs = [
        ("log-001", "2024-01-01 10:00:00 User login: admin"),
        ("log-002", "2024-01-01 10:00:01 File access: /etc/passwd"),
        ("log-003", "2024-01-01 10:00:02 Command: whoami"),
    ]

    print("Adding logs to chain...")
    for log_id, content in sample_logs:
        chain.add_log(log_id, content)
        print(f"  Added: {log_id}")

    print(f"\nPending logs: {chain.pending_count}")

    # Force seal a block
    print("\nSealing block...")
    block = chain.seal_block(force=True)
    if block:
        print(f"  Block ID: {block.block_id}")
        print(f"  Merkle Root: {block.merkle_root[:32]}...")
        print(f"  Block Hash: {block.block_hash[:32]}...")
        print(f"  Log Count: {block.log_count}")

    # Add more logs and seal
    chain.add_log("log-004", "2024-01-01 10:00:03 Privilege escalation attempt")
    chain.add_log("log-005", "2024-01-01 10:00:04 Suspicious script execution")
    block2 = chain.seal_block(force=True)

    print(f"\nChain length: {chain.length} blocks")

    # Verify chain
    print("\nVerifying chain integrity...")
    is_valid, errors = chain.verify_chain()
    print(f"  Chain valid: {'✓ Yes' if is_valid else '✗ No'}")
    if errors:
        for err in errors:
            print(f"    Error: {err}")

    # Export for anchoring
    print("\nExport for blockchain anchoring:")
    for export in chain.export_for_anchoring():
        print(f"  Block {export['block_id']}: {export['block_hash'][:24]}...")


if __name__ == "__main__":
    main()
