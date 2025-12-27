"""
Tests for Merkle Tree and LogChain.
"""

import pytest
from forensic_framework.integrity import MerkleTree, LogChain


class TestMerkleTree:
    """Test Merkle Tree implementation."""

    def test_build_tree(self):
        tree = MerkleTree()
        tree.add_leaf("log1")
        tree.add_leaf("log2")
        tree.add_leaf("log3")
        tree.add_leaf("log4")

        root = tree.build()

        assert root is not None
        assert len(root) == 64  # SHA-256 hex length

    def test_root_changes_with_data(self):
        tree1 = MerkleTree()
        tree1.add_leaf("log1")
        tree1.add_leaf("log2")
        root1 = tree1.build()

        tree2 = MerkleTree()
        tree2.add_leaf("log1")
        tree2.add_leaf("log3")  # Different data
        root2 = tree2.build()

        assert root1 != root2

    def test_generate_and_verify_proof(self):
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(f"log{i}")
        tree.build()

        proof = tree.get_proof(3)
        assert tree.verify_proof(proof)

    def test_invalid_proof_fails(self):
        tree = MerkleTree()
        for i in range(4):
            tree.add_leaf(f"log{i}")
        tree.build()

        proof = tree.get_proof(0)
        # Tamper with the proof
        proof.leaf_hash = tree._hash("tampered")

        assert not tree.verify_proof(proof)

    def test_single_leaf_tree(self):
        tree = MerkleTree()
        tree.add_leaf("single_log")
        root = tree.build()

        assert root is not None
        proof = tree.get_proof(0)
        assert tree.verify_proof(proof)


class TestLogChain:
    """Test LogChain implementation."""

    def test_add_and_seal_block(self):
        chain = LogChain()

        chain.add_log("log-001", "Log content 1")
        chain.add_log("log-002", "Log content 2")
        chain.add_log("log-003", "Log content 3")

        block = chain.seal_block(force=True)

        assert block is not None
        assert block.block_id == 0
        assert block.log_count == 3
        assert len(block.merkle_root) == 64

    def test_chain_grows(self):
        chain = LogChain()

        # First block
        chain.add_log("log-1", "Content 1")
        chain.seal_block(force=True)

        # Second block
        chain.add_log("log-2", "Content 2")
        chain.seal_block(force=True)

        assert chain.length == 2

    def test_chain_links(self):
        chain = LogChain()

        chain.add_log("log-1", "Content 1")
        block1 = chain.seal_block(force=True)

        chain.add_log("log-2", "Content 2")
        block2 = chain.seal_block(force=True)

        # Block 2 should reference Block 1's hash
        assert block2.prev_block_hash == block1.block_hash

    def test_verify_valid_chain(self):
        chain = LogChain()

        for i in range(3):
            chain.add_log(f"log-{i}", f"Content {i}")
            chain.seal_block(force=True)

        is_valid, errors = chain.verify_chain()
        assert is_valid
        assert len(errors) == 0

    def test_export_for_anchoring(self):
        chain = LogChain()

        chain.add_log("log-1", "Content 1")
        chain.seal_block(force=True)

        export = chain.export_for_anchoring()

        assert len(export) == 1
        assert "block_id" in export[0]
        assert "merkle_root" in export[0]
        assert "block_hash" in export[0]
