"""
Tests for Drain3 parser.
"""

import pytest
from forensic_framework.ingestion import DrainParser, LogPreprocessor


class TestLogPreprocessor:
    """Test log preprocessing."""

    def test_mask_ipv4(self):
        preprocessor = LogPreprocessor()
        result = preprocessor.preprocess("Failed login from 192.168.1.100")

        assert "<*>" in result.masked
        assert "192.168.1.100" in result.entities.get("ipv4", [])

    def test_mask_guid(self):
        preprocessor = LogPreprocessor()
        result = preprocessor.preprocess(
            "Request ID: 550e8400-e29b-41d4-a716-446655440000"
        )

        assert "<*>" in result.masked
        assert "550e8400-e29b-41d4-a716-446655440000" in result.entities.get("guid", [])

    def test_mask_multiple_entities(self):
        preprocessor = LogPreprocessor()
        result = preprocessor.preprocess(
            "Connection from 10.0.0.1 to 10.0.0.2 port 22"
        )

        assert result.masked.count("<*>") >= 2
        assert len(result.entities.get("ipv4", [])) >= 2

    def test_preserve_structure(self):
        preprocessor = LogPreprocessor()
        result = preprocessor.preprocess("Failed password for root from 192.168.1.1")

        assert "Failed password for root from" in result.masked
        assert result.masked.endswith("<*>")


class TestDrainParser:
    """Test Drain3 parser."""

    def test_parse_single_log(self):
        parser = DrainParser()
        result = parser.parse("Failed password for root from 192.168.1.100 port 22 ssh2")

        assert "template_id" in result
        assert "template" in result
        assert "<*>" in result["template"]

    def test_parse_similar_logs(self):
        parser = DrainParser()

        result1 = parser.parse("Failed password for root from 192.168.1.100 port 22 ssh2")
        result2 = parser.parse("Failed password for admin from 10.0.0.50 port 22 ssh2")

        # Similar logs should get the same template
        assert result1["template_id"] == result2["template_id"]

    def test_parse_different_logs(self):
        parser = DrainParser()

        result1 = parser.parse("Failed password for root from 192.168.1.100 port 22 ssh2")
        result2 = parser.parse("Session opened for user admin by root(uid=0)")

        # Different logs should get different templates
        assert result1["template_id"] != result2["template_id"]

    def test_get_cluster_templates(self):
        parser = DrainParser()

        parser.parse("Log entry 1")
        parser.parse("Log entry 2")
        parser.parse("Different log format")

        templates = parser.get_cluster_templates()
        assert len(templates) >= 1
        assert all("cluster_id" in t for t in templates)

    def test_get_stats(self):
        parser = DrainParser()

        for i in range(10):
            parser.parse(f"Log entry {i}")

        stats = parser.get_stats()
        assert stats["total_logs_parsed"] == 10
        assert stats["total_clusters"] >= 1
