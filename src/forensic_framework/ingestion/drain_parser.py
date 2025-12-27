"""
Drain3-based log parser for automated template extraction.

Drain3 uses a fixed-depth parse tree to group similar logs into "templates".
This is research-backed with tuned parameters for optimal performance.
"""

from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from ..config import get_settings
from .preprocessor import LogPreprocessor
from .schemas import ParsedLog, RawLogEntry


class DrainParser:
    """
    Drain3-based log parser with preprocessing.

    Key Configuration (Research-Backed):
    - depth=4: Balances speed with handling deep nested paths
    - sim_th=0.4: Prevents template explosion while maintaining accuracy
    - Preprocessing: Masks variables before parsing for lean templates
    """

    def __init__(
        self,
        depth: int | None = None,
        sim_th: float | None = None,
        max_children: int | None = None,
        max_clusters: int | None = None,
        state_file: Path | None = None,
        preprocessor: LogPreprocessor | None = None,
    ):
        """
        Initialize the Drain parser.

        Args:
            depth: Parse tree depth (default: 4)
            sim_th: Similarity threshold (default: 0.4)
            max_children: Max children per parse tree node
            max_clusters: Max number of log clusters/templates
            state_file: Path to persist Drain3 state
            preprocessor: Custom preprocessor (uses default if None)
        """
        settings = get_settings()

        self.depth = depth or settings.drain_depth
        self.sim_th = sim_th or settings.drain_sim_th
        self.max_children = max_children or settings.drain_max_children
        self.max_clusters = max_clusters or settings.drain_max_clusters
        self.state_file = state_file or settings.drain_state_file

        # Initialize preprocessor
        self.preprocessor = preprocessor or LogPreprocessor()

        # Configure Drain3
        self._config = self._create_config()
        self._miner = TemplateMiner(config=self._config)

        # Load existing state if available
        self._load_state()

    def _create_config(self) -> TemplateMinerConfig:
        """Create Drain3 configuration."""
        config = TemplateMinerConfig()

        # Core algorithm settings
        config.drain_depth = self.depth
        config.drain_sim_th = self.sim_th
        config.drain_max_children = self.max_children
        config.drain_max_clusters = self.max_clusters

        # Use extra delimiters for better parsing
        config.drain_extra_delimiters = ["_", "-", "=", "/", "\\", ":", "@"]

        # Parameterize common variable patterns
        config.masking = [
            {"regex_pattern": r"<\*>", "mask_with": "<*>"},  # Keep our preprocessor masks
        ]

        return config

    def _load_state(self) -> None:
        """Load persisted state if available."""
        if self.state_file and self.state_file.exists():
            try:
                with open(self.state_file, "rb") as f:
                    self._miner.load_state(f.read())
            except Exception:
                pass  # Start fresh if state is corrupted

    def save_state(self) -> None:
        """Persist Drain3 state to disk."""
        if self.state_file:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            state = self._miner.get_snapshot()
            with open(self.state_file, "wb") as f:
                f.write(state)

    def parse(self, message: str) -> dict[str, Any]:
        """
        Parse a single log message.

        Args:
            message: Raw log message.

        Returns:
            Dict with template_id, template, and parameters.
        """
        # Preprocess to mask variables
        preprocessed = self.preprocessor.preprocess(message)

        # Parse with Drain3
        result = self._miner.add_log_message(preprocessed.masked)

        # Handle both object and dict-like responses from different Drain3 versions
        if hasattr(result, 'cluster_id'):
            cluster_id = result.cluster_id
            template = result.get_template() if hasattr(result, 'get_template') else str(result)
            parameters = result.get_variables() if hasattr(result, 'get_variables') else []
            change_type = result.change_type if hasattr(result, 'change_type') else "unknown"
        else:
            # Fallback for dict-like response
            cluster_id = result.get('cluster_id', 0) if isinstance(result, dict) else 0
            template = result.get('template', preprocessed.masked) if isinstance(result, dict) else preprocessed.masked
            parameters = result.get('variables', []) if isinstance(result, dict) else []
            change_type = result.get('change_type', 'unknown') if isinstance(result, dict) else 'unknown'

        return {
            "template_id": cluster_id,
            "template": template,
            "parameters": parameters or [],
            "masked_message": preprocessed.masked,
            "entities": preprocessed.entities,
            "change_type": change_type,
        }

    def parse_entry(self, entry: RawLogEntry) -> ParsedLog:
        """
        Parse a RawLogEntry into a ParsedLog.

        Args:
            entry: Raw log entry with metadata.

        Returns:
            ParsedLog with template and extracted data.
        """
        result = self.parse(entry.raw_message)

        return ParsedLog(
            ingestion_id=entry.ingestion_id,
            arrival_timestamp=entry.arrival_timestamp,
            template_id=result["template_id"],
            template=result["template"],
            parameters=result["parameters"],
            masked_message=result["masked_message"],
            severity=entry.severity or "INFO",
            log_type=entry.source_type,
            entities=result["entities"],
        )

    def parse_batch(self, messages: list[str]) -> list[dict[str, Any]]:
        """Parse a batch of log messages."""
        return [self.parse(msg) for msg in messages]

    def get_cluster_templates(self) -> list[dict[str, Any]]:
        """Get all discovered log templates."""
        clusters = self._miner.drain.clusters
        return [
            {
                "cluster_id": cluster.cluster_id,
                "template": " ".join(cluster.log_template_tokens),
                "size": cluster.size,
            }
            for cluster in clusters
        ]

    def get_stats(self) -> dict[str, Any]:
        """Get parsing statistics."""
        clusters = self._miner.drain.clusters
        return {
            "total_clusters": len(clusters),
            "total_logs_parsed": sum(c.size for c in clusters),
            "depth": self.depth,
            "sim_th": self.sim_th,
        }


# Convenience function for CLI usage
def main():
    """Demo Drain3 parsing with sample logs."""
    sample_logs = [
        "Failed password for root from 192.168.1.100 port 22 ssh2",
        "Failed password for admin from 10.0.0.50 port 22 ssh2",
        "Accepted publickey for user1 from 172.16.0.1 port 54321 ssh2",
        "Connection closed by 192.168.1.100 port 22 [preauth]",
        "session opened for user root by root(uid=0)",
        "session opened for user admin by admin(uid=1000)",
        "error: maximum authentication attempts exceeded for root from 192.168.1.100 port 22 ssh2",
    ]

    parser = DrainParser()

    print("Parsing sample logs with Drain3...\n")
    for log in sample_logs:
        result = parser.parse(log)
        print(f"Log: {log}")
        print(f"  Template ID: {result['template_id']}")
        print(f"  Template: {result['template']}")
        print(f"  Params: {result['parameters']}")
        print(f"  Entities: {result['entities']}")
        print()

    print("\nDiscovered Templates:")
    for template in parser.get_cluster_templates():
        print(f"  [{template['cluster_id']}] ({template['size']} logs): {template['template']}")

    print(f"\nStats: {parser.get_stats()}")


if __name__ == "__main__":
    main()
