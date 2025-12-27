"""
Anomaly Detection using statistical and ML-based methods.

This module provides anomaly detection for log sequences using:
1. Statistical methods (Z-score, IQR)
2. Isolation Forest (sklearn)
3. Sequence-based detection (LogBERT-style, optional)

The focus is on detecting:
- Unusual time patterns
- Abnormal frequency of events
- Rare template sequences
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class AnomalyResult:
    """Result of anomaly detection for a log entry."""

    log_id: str
    score: float  # 0.0 to 1.0 (higher = more anomalous)
    is_anomaly: bool
    detection_method: str
    features: dict[str, float] = field(default_factory=dict)
    explanation: str | None = None


class FeatureExtractor:
    """
    Extract numerical features from log entries for anomaly detection.

    Features include:
    - Time-based: hour of day, day of week, time since last event
    - Frequency-based: template frequency, source frequency
    - Content-based: message length, parameter count
    """

    def __init__(self):
        """Initialize feature extractor."""
        self.template_counts: dict[int, int] = {}
        self.source_counts: dict[str, int] = {}
        self.severity_map = {
            "DEBUG": 0,
            "INFO": 1,
            "WARNING": 2,
            "ERROR": 3,
            "CRITICAL": 4,
        }
        self._last_timestamp: datetime | None = None

    def extract(self, log_entry: dict[str, Any]) -> dict[str, float]:
        """
        Extract features from a log entry.

        Args:
            log_entry: Log entry with fields like timestamp, template_id, etc.

        Returns:
            Dictionary of feature names to values
        """
        features: dict[str, float] = {}

        # Time-based features
        timestamp = log_entry.get("arrival_timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        if timestamp:
            features["hour_of_day"] = timestamp.hour
            features["day_of_week"] = timestamp.weekday()
            features["minute_of_hour"] = timestamp.minute

            # Time since last event
            if self._last_timestamp:
                delta = (timestamp - self._last_timestamp).total_seconds()
                features["time_since_last"] = min(delta, 3600)  # Cap at 1 hour
            else:
                features["time_since_last"] = 0

            self._last_timestamp = timestamp

        # Template frequency (rarity)
        template_id = log_entry.get("template_id", 0)
        self.template_counts[template_id] = self.template_counts.get(template_id, 0) + 1
        total_templates = sum(self.template_counts.values())
        features["template_frequency"] = self.template_counts[template_id] / max(total_templates, 1)
        features["template_rarity"] = 1.0 - features["template_frequency"]

        # Source frequency
        source = log_entry.get("source_host", "unknown")
        self.source_counts[source] = self.source_counts.get(source, 0) + 1
        total_sources = sum(self.source_counts.values())
        features["source_frequency"] = self.source_counts[source] / max(total_sources, 1)

        # Severity
        severity = log_entry.get("severity", "INFO")
        features["severity_level"] = self.severity_map.get(severity.upper(), 1)

        # Content features
        message = log_entry.get("masked_message", log_entry.get("raw_message", ""))
        features["message_length"] = len(message)

        parameters = log_entry.get("parameters", [])
        features["parameter_count"] = len(parameters) if isinstance(parameters, list) else 0

        # Entity counts
        entities = log_entry.get("entities", {})
        features["ip_count"] = len(entities.get("ipv4", []) + entities.get("ipv6", []))
        features["path_count"] = len(entities.get("path", []))

        return features

    def reset(self) -> None:
        """Reset accumulated statistics."""
        self.template_counts = {}
        self.source_counts = {}
        self._last_timestamp = None


class AnomalyDetector:
    """
    Anomaly detection for forensic log analysis.

    Combines multiple detection methods:
    1. Statistical (Z-score based)
    2. Isolation Forest (unsupervised ML)

    Usage:
        detector = AnomalyDetector()
        detector.fit(training_logs)
        results = detector.detect(new_logs)
    """

    def __init__(
        self,
        method: Literal["isolation_forest", "statistical", "combined"] = "combined",
        contamination: float = 0.1,
        threshold: float = 0.7,
    ):
        """
        Initialize anomaly detector.

        Args:
            method: Detection method to use
            contamination: Expected proportion of anomalies (for IF)
            threshold: Score threshold for marking as anomaly
        """
        self.method = method
        self.contamination = contamination
        self.threshold = threshold

        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )

        self._is_fitted = False
        self._feature_names: list[str] = []

    def _logs_to_features(self, logs: list[dict[str, Any]]) -> np.ndarray:
        """Convert logs to feature matrix."""
        self.feature_extractor.reset()
        feature_dicts = [self.feature_extractor.extract(log) for log in logs]

        if not feature_dicts:
            return np.array([])

        self._feature_names = list(feature_dicts[0].keys())
        return np.array([
            [fd[name] for name in self._feature_names]
            for fd in feature_dicts
        ])

    def fit(self, logs: list[dict[str, Any]]) -> None:
        """
        Fit the detector on training logs (assumed to be mostly normal).

        Args:
            logs: List of log entries for training
        """
        if len(logs) < 10:
            raise ValueError("Need at least 10 logs for training")

        X = self._logs_to_features(logs)

        # Fit scaler
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)

        # Fit Isolation Forest
        if self.method in ["isolation_forest", "combined"]:
            self.isolation_forest.fit(X_scaled)

        self._is_fitted = True

    def detect(self, logs: list[dict[str, Any]]) -> list[AnomalyResult]:
        """
        Detect anomalies in log entries.

        Args:
            logs: List of log entries to analyze

        Returns:
            List of AnomalyResult for each log
        """
        if not self._is_fitted:
            raise RuntimeError("Detector must be fitted first")

        self.feature_extractor.reset()
        results: list[AnomalyResult] = []

        for log in logs:
            features = self.feature_extractor.extract(log)
            X = np.array([[features[name] for name in self._feature_names]])
            X_scaled = self.scaler.transform(X)

            # Calculate anomaly score
            if self.method == "isolation_forest":
                score = self._isolation_forest_score(X_scaled)
            elif self.method == "statistical":
                score = self._statistical_score(X_scaled)
            else:  # combined
                if_score = self._isolation_forest_score(X_scaled)
                stat_score = self._statistical_score(X_scaled)
                score = (if_score + stat_score) / 2

            is_anomaly = score >= self.threshold

            # Generate explanation
            explanation = self._generate_explanation(features, score, is_anomaly)

            results.append(AnomalyResult(
                log_id=log.get("ingestion_id", str(len(results))),
                score=score,
                is_anomaly=is_anomaly,
                detection_method=self.method,
                features=features,
                explanation=explanation,
            ))

        return results

    def _isolation_forest_score(self, X_scaled: np.ndarray) -> float:
        """Calculate Isolation Forest anomaly score."""
        # IF returns -1 for anomaly, 1 for normal
        raw_score = self.isolation_forest.score_samples(X_scaled)[0]
        # Convert to 0-1 range (more negative = more anomalous)
        # Typical range is -0.5 to 0.5
        normalized = (0.5 - raw_score) / 1.0
        return np.clip(normalized, 0.0, 1.0)

    def _statistical_score(self, X_scaled: np.ndarray) -> float:
        """Calculate statistical anomaly score using Z-scores."""
        # Average absolute Z-score
        z_scores = np.abs(X_scaled[0])
        avg_z = np.mean(z_scores)
        # Convert to 0-1 range (Z > 3 is highly anomalous)
        return np.clip(avg_z / 4.0, 0.0, 1.0)

    def _generate_explanation(
        self,
        features: dict[str, float],
        score: float,
        is_anomaly: bool,
    ) -> str:
        """Generate human-readable explanation."""
        if not is_anomaly:
            return "No significant anomalies detected."

        # Find top contributing factors
        explanations = []

        if features.get("template_rarity", 0) > 0.9:
            explanations.append("Rare log template (unusual event type)")

        if features.get("severity_level", 0) >= 3:
            explanations.append("High severity level (ERROR or CRITICAL)")

        hour = features.get("hour_of_day", 12)
        if hour < 6 or hour > 22:
            explanations.append(f"Unusual time of day ({int(hour)}:00)")

        if features.get("time_since_last", 0) < 0.1:
            explanations.append("Rapid succession of events")

        if features.get("ip_count", 0) > 2:
            explanations.append("Multiple IP addresses involved")

        if not explanations:
            explanations.append("Statistical deviation from normal patterns")

        return f"Anomaly Score: {score:.2f}. " + " | ".join(explanations)


def main():
    """Demo anomaly detection."""
    print("Anomaly Detector Demo\n")

    # Generate sample training data (normal logs)
    normal_logs = [
        {
            "ingestion_id": f"log-{i}",
            "arrival_timestamp": datetime.now() - timedelta(hours=i),
            "template_id": i % 5,  # 5 common templates
            "severity": "INFO",
            "source_host": f"server-{i % 3}",
            "masked_message": f"Normal operation {i}",
            "parameters": ["param1"],
            "entities": {},
        }
        for i in range(100)
    ]

    # Create some anomalous logs
    anomalous_logs = [
        {
            "ingestion_id": "anomaly-1",
            "arrival_timestamp": datetime.now().replace(hour=3),  # Unusual hour
            "template_id": 999,  # Rare template
            "severity": "CRITICAL",
            "source_host": "unknown-server",
            "masked_message": "Suspicious activity detected" * 10,
            "parameters": ["a", "b", "c", "d", "e"],
            "entities": {"ipv4": ["1.2.3.4", "5.6.7.8", "9.10.11.12"]},
        },
        {
            "ingestion_id": "anomaly-2",
            "arrival_timestamp": datetime.now().replace(hour=4),
            "template_id": 998,
            "severity": "ERROR",
            "source_host": "unknown-server",
            "masked_message": "Failed authentication attempt",
            "parameters": [],
            "entities": {"ipv4": ["192.168.1.1"]},
        },
    ]

    # Train detector
    detector = AnomalyDetector(method="combined", threshold=0.5)
    print("Training anomaly detector on normal logs...")
    detector.fit(normal_logs)
    print(f"  Trained on {len(normal_logs)} logs\n")

    # Detect anomalies
    test_logs = normal_logs[-10:] + anomalous_logs
    print("Detecting anomalies in test set...")
    results = detector.detect(test_logs)

    for result in results:
        status = "🚨 ANOMALY" if result.is_anomaly else "✓ Normal"
        print(f"  [{result.log_id}] Score: {result.score:.2f} - {status}")
        if result.is_anomaly:
            print(f"    Explanation: {result.explanation}")


if __name__ == "__main__":
    main()
