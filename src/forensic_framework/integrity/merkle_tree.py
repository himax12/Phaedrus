"""
Merkle Tree implementation for forensic log integrity.

A Merkle Tree is a hash tree where each leaf node is a hash of a data block,
and each non-leaf node is a hash of its children. The root hash (Merkle Root)
provides a unique fingerprint for the entire dataset.

Key Properties:
- Tamper Detection: Any modification changes the root hash
- Efficient Proofs: Verify individual items without full dataset
- ISO 27037 Compliance: Provides cryptographic evidence integrity
"""

import hashlib
from dataclasses import dataclass, field
from typing import Literal

from ..config import get_settings


@dataclass
class MerkleProof:
    """Proof that a leaf is part of the Merkle Tree."""

    leaf_hash: str
    leaf_index: int
    proof_hashes: list[str]
    proof_directions: list[Literal["left", "right"]]
    root_hash: str

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "proof_hashes": self.proof_hashes,
            "proof_directions": self.proof_directions,
            "root_hash": self.root_hash,
        }


class MerkleTree:
    """
    Merkle Tree for cryptographic integrity verification.

    Usage:
        tree = MerkleTree()
        for log in logs:
            tree.add_leaf(log)
        root = tree.build()
        proof = tree.get_proof(0)
        is_valid = tree.verify_proof(proof)
    """

    def __init__(
        self,
        hash_algorithm: Literal["sha256", "sha512"] | None = None,
    ):
        """
        Initialize Merkle Tree.

        Args:
            hash_algorithm: Hash algorithm to use (default: sha256)
        """
        settings = get_settings()
        self.algorithm = hash_algorithm or settings.hash_algorithm
        self._leaves: list[str] = []
        self._tree: list[list[str]] = []
        self._built = False

    def _hash(self, data: str | bytes) -> str:
        """Compute hash of data."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        if self.algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif self.algorithm == "sha512":
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def _hash_pair(self, left: str, right: str) -> str:
        """Hash a pair of hashes."""
        return self._hash(left + right)

    def add_leaf(self, data: str) -> str:
        """
        Add a leaf to the tree.

        Args:
            data: Data to add (will be hashed)

        Returns:
            Hash of the added leaf
        """
        if self._built:
            raise RuntimeError("Cannot add leaves after tree is built")

        leaf_hash = self._hash(data)
        self._leaves.append(leaf_hash)
        return leaf_hash

    def add_leaf_hash(self, leaf_hash: str) -> None:
        """Add a pre-computed leaf hash."""
        if self._built:
            raise RuntimeError("Cannot add leaves after tree is built")
        self._leaves.append(leaf_hash)

    def build(self) -> str:
        """
        Build the Merkle Tree and return the root hash.

        Returns:
            Merkle Root hash
        """
        if not self._leaves:
            raise ValueError("Cannot build empty tree")

        # Start with leaves
        self._tree = [self._leaves.copy()]

        current_level = self._leaves.copy()

        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []

            # Pad with duplicate if odd number
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            # Hash pairs
            for i in range(0, len(current_level), 2):
                parent = self._hash_pair(current_level[i], current_level[i + 1])
                next_level.append(parent)

            self._tree.append(next_level)
            current_level = next_level

        self._built = True
        return current_level[0]

    @property
    def root(self) -> str | None:
        """Get the Merkle Root (None if not built)."""
        if not self._built or not self._tree:
            return None
        return self._tree[-1][0]

    @property
    def leaf_count(self) -> int:
        """Get number of leaves."""
        return len(self._leaves)

    def get_proof(self, leaf_index: int) -> MerkleProof:
        """
        Generate a Merkle Proof for a leaf.

        Args:
            leaf_index: Index of the leaf (0-based)

        Returns:
            MerkleProof object for verification
        """
        if not self._built:
            raise RuntimeError("Tree must be built first")

        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range")

        proof_hashes: list[str] = []
        proof_directions: list[Literal["left", "right"]] = []

        index = leaf_index

        for level in self._tree[:-1]:  # Exclude root level
            # Pad level if needed (for consistent indexing)
            padded_level = level.copy()
            if len(padded_level) % 2 != 0:
                padded_level.append(padded_level[-1])

            # Get sibling
            if index % 2 == 0:
                # Current is left child, sibling is right
                sibling_index = index + 1
                direction: Literal["left", "right"] = "right"
            else:
                # Current is right child, sibling is left
                sibling_index = index - 1
                direction = "left"

            if sibling_index < len(padded_level):
                proof_hashes.append(padded_level[sibling_index])
                proof_directions.append(direction)

            # Move to parent index
            index = index // 2

        return MerkleProof(
            leaf_hash=self._leaves[leaf_index],
            leaf_index=leaf_index,
            proof_hashes=proof_hashes,
            proof_directions=proof_directions,
            root_hash=self.root or "",
        )

    def verify_proof(self, proof: MerkleProof) -> bool:
        """
        Verify a Merkle Proof.

        Args:
            proof: MerkleProof to verify

        Returns:
            True if proof is valid
        """
        current_hash = proof.leaf_hash

        for sibling_hash, direction in zip(
            proof.proof_hashes, proof.proof_directions
        ):
            if direction == "left":
                current_hash = self._hash_pair(sibling_hash, current_hash)
            else:
                current_hash = self._hash_pair(current_hash, sibling_hash)

        return current_hash == proof.root_hash

    @classmethod
    def verify_data(
        cls,
        data: str,
        proof: MerkleProof,
        algorithm: Literal["sha256", "sha512"] = "sha256",
    ) -> bool:
        """
        Verify that data belongs to a Merkle Tree using a proof.

        Args:
            data: Original data (not hashed)
            proof: MerkleProof for verification
            algorithm: Hash algorithm used

        Returns:
            True if data is verified as part of the tree
        """
        tree = cls(hash_algorithm=algorithm)
        data_hash = tree._hash(data)

        if data_hash != proof.leaf_hash:
            return False

        return tree.verify_proof(proof)


def main():
    """Demo Merkle Tree functionality."""
    print("Merkle Tree Demo\n")

    # Create tree with sample log hashes
    logs = [
        "2024-01-01 10:00:00 User login: admin",
        "2024-01-01 10:00:01 File access: /etc/passwd",
        "2024-01-01 10:00:02 Command executed: ls -la",
        "2024-01-01 10:00:03 User logout: admin",
    ]

    tree = MerkleTree()

    print("Adding logs to Merkle Tree:")
    for i, log in enumerate(logs):
        leaf_hash = tree.add_leaf(log)
        print(f"  [{i}] {log[:40]}...")
        print(f"      Hash: {leaf_hash[:32]}...")

    root = tree.build()
    print(f"\nMerkle Root: {root}")

    # Generate and verify proof
    print("\nGenerating proof for log[1]...")
    proof = tree.get_proof(1)
    print(f"  Leaf Hash: {proof.leaf_hash[:32]}...")
    print(f"  Proof Path: {len(proof.proof_hashes)} hashes")

    is_valid = tree.verify_proof(proof)
    print(f"  Verification: {'✓ Valid' if is_valid else '✗ Invalid'}")

    # Demonstrate tamper detection
    print("\nTamper Detection Demo:")
    tampered_proof = MerkleProof(
        leaf_hash=tree._hash("TAMPERED DATA"),
        leaf_index=proof.leaf_index,
        proof_hashes=proof.proof_hashes,
        proof_directions=proof.proof_directions,
        root_hash=proof.root_hash,
    )
    is_valid_tampered = tree.verify_proof(tampered_proof)
    print(f"  Tampered proof verification: {'✓ Valid' if is_valid_tampered else '✗ Invalid (Tamper Detected!)'}")


if __name__ == "__main__":
    main()
