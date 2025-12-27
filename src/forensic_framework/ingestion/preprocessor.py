"""
Log preprocessor with variable masking.

Critical preprocessing step before Drain3 parsing to keep
the parse tree lean and improve template accuracy.
"""

import re
from dataclasses import dataclass, field
from typing import Pattern


@dataclass
class MaskingRule:
    """A rule for masking variable patterns in logs."""

    name: str
    pattern: Pattern[str]
    replacement: str = "<*>"


@dataclass
class PreprocessResult:
    """Result of preprocessing a log message."""

    original: str
    masked: str
    entities: dict[str, list[str]] = field(default_factory=dict)


class LogPreprocessor:
    """
    Preprocessor that masks variables in log messages before Drain3 parsing.

    This is a critical step that:
    1. Extracts entities (IPs, GUIDs, hex codes) for later analysis
    2. Replaces them with <*> placeholders for consistent template matching
    3. Keeps the Drain3 parse tree lean and focused on structure
    """

    # Default masking rules (order matters - more specific first)
    DEFAULT_RULES: list[MaskingRule] = [
        # IPv6 addresses (must come before IPv4)
        MaskingRule(
            name="ipv6",
            pattern=re.compile(
                r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
                r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
                r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}",
                re.IGNORECASE,
            ),
        ),
        # IPv4 addresses
        MaskingRule(
            name="ipv4",
            pattern=re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
        ),
        # GUIDs/UUIDs
        MaskingRule(
            name="guid",
            pattern=re.compile(
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
                re.IGNORECASE,
            ),
        ),
        # Hex strings (8+ chars)
        MaskingRule(
            name="hex",
            pattern=re.compile(r"\b0x[0-9a-fA-F]{8,}\b|\b[0-9a-fA-F]{16,}\b"),
        ),
        # Email addresses
        MaskingRule(
            name="email",
            pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        ),
        # File paths (Unix and Windows)
        MaskingRule(
            name="path",
            pattern=re.compile(
                r'(?:/[^\s/:"*?<>|]+)+|'  # Unix paths
                r"[A-Za-z]:\\(?:[^\s\\/:*?\"<>|]+\\)*[^\s\\/:*?\"<>|]*"  # Windows paths
            ),
        ),
        # URLs
        MaskingRule(
            name="url",
            pattern=re.compile(
                r"https?://[^\s<>\"{}|\\^`\[\]]+"
            ),
        ),
        # MAC addresses
        MaskingRule(
            name="mac",
            pattern=re.compile(
                r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
            ),
        ),
        # Timestamps (common formats)
        MaskingRule(
            name="timestamp",
            pattern=re.compile(
                r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b|"
                r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
            ),
        ),
        # Port numbers (when preceded by "port" or ":")
        MaskingRule(
            name="port",
            pattern=re.compile(r"(?<=port\s)\d{1,5}\b|(?<=:)\d{1,5}\b"),
        ),
        # Large numbers (likely IDs, PIDs, etc.)
        MaskingRule(
            name="number",
            pattern=re.compile(r"\b\d{5,}\b"),  # 5+ digit numbers
        ),
    ]

    def __init__(
        self,
        rules: list[MaskingRule] | None = None,
        extract_entities: bool = True,
    ):
        """
        Initialize the preprocessor.

        Args:
            rules: Custom masking rules. Uses defaults if None.
            extract_entities: Whether to extract and store entities before masking.
        """
        self.rules = rules or self.DEFAULT_RULES.copy()
        self.extract_entities = extract_entities

    def add_rule(self, name: str, pattern: str, replacement: str = "<*>") -> None:
        """Add a custom masking rule."""
        self.rules.insert(
            0,  # Insert at beginning (higher priority)
            MaskingRule(name=name, pattern=re.compile(pattern), replacement=replacement),
        )

    def preprocess(self, message: str) -> PreprocessResult:
        """
        Preprocess a log message by masking variables.

        Args:
            message: Raw log message.

        Returns:
            PreprocessResult with original, masked message, and extracted entities.
        """
        entities: dict[str, list[str]] = {}
        masked = message

        for rule in self.rules:
            if self.extract_entities:
                # Find all matches before replacing
                matches = rule.pattern.findall(masked)
                if matches:
                    if rule.name not in entities:
                        entities[rule.name] = []
                    entities[rule.name].extend(matches)

            # Replace with placeholder
            masked = rule.pattern.sub(rule.replacement, masked)

        return PreprocessResult(
            original=message,
            masked=masked,
            entities=entities,
        )

    def preprocess_batch(self, messages: list[str]) -> list[PreprocessResult]:
        """Preprocess a batch of messages."""
        return [self.preprocess(msg) for msg in messages]
